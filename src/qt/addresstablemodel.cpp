// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/addresstablemodel.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <addresstype.h>
#include <key_io.h>
#include <wallet/types.h>
#include <wallet/wallet.h>

#include <algorithm>

#include <QColor>
#include <QFont>
#include <QDebug>

const QString AddressTableModel::Send = "S";
const QString AddressTableModel::Receive = "R";

static constexpr int MAX_VISIBLE_UNLABELED_RECEIVE_ADDRESSES = 2000;

struct AddressTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Hidden /* QSortFilterProxyModel will filter these out */
    };

    Type type;
    QString label;
    QString address;

    AddressTableEntry() = default;
    AddressTableEntry(Type _type, const QString &_label, const QString &_address):
        type(_type), label(_label), address(_address) {}
};

struct AddressTableEntryLessThan
{
    bool operator()(const AddressTableEntry &a, const AddressTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const AddressTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const AddressTableEntry &b) const
    {
        return a < b.address;
    }
};

/* Determine address type from address purpose */
constexpr AddressTableEntry::Type translateTransactionType(wallet::AddressPurpose purpose, bool isMine)
{
    // "refund" addresses aren't shown, and change addresses aren't returned by getAddresses at all.
    switch (purpose) {
    case wallet::AddressPurpose::SEND: return AddressTableEntry::Sending;
    case wallet::AddressPurpose::RECEIVE: return AddressTableEntry::Receiving;
    case wallet::AddressPurpose::REFUND: return AddressTableEntry::Hidden;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

// Private implementation
class AddressTablePriv
{
public:
    QList<AddressTableEntry> cachedAddressTable;
    AddressTableModel *parent;
    bool m_pk_hash_only{false};
    bool m_hide_unlabeled_receives{false};

    explicit AddressTablePriv(AddressTableModel *_parent, bool pk_hash_only):
        parent(_parent), m_pk_hash_only(pk_hash_only) {}

    bool shouldShowAddress(const CTxDestination& dest, const std::string& label, wallet::AddressPurpose purpose) const
    {
        if (m_pk_hash_only && !std::holds_alternative<PKHash>(dest)) {
            return false;
        }
        if (m_hide_unlabeled_receives && purpose == wallet::AddressPurpose::RECEIVE && label.empty()) {
            return false;
        }
        return true;
    }

    void refreshAddressTable(interfaces::Wallet& wallet)
    {
        cachedAddressTable.clear();
        {
            const auto addresses = wallet.getAddresses();
            const auto unlabeled_receive_count = std::count_if(addresses.begin(), addresses.end(), [](const auto& address) {
                return address.purpose == wallet::AddressPurpose::RECEIVE && address.name.empty();
            });
            m_hide_unlabeled_receives = unlabeled_receive_count > MAX_VISIBLE_UNLABELED_RECEIVE_ADDRESSES;
            if (m_hide_unlabeled_receives) {
                qWarning() << "AddressTablePriv::refreshAddressTable: hiding"
                           << unlabeled_receive_count
                           << "unlabeled receive addresses from the GUI address table";
            }

            for (const auto& address : addresses)
            {
                AddressTableEntry::Type addressType = translateTransactionType(
                        address.purpose, address.is_mine);
                if (!shouldShowAddress(address.dest, address.name, address.purpose)) {
                    continue;
                }

                // Add [PQ] badge to label if it's a witness v2 ML-DSA address
                QString label = QString::fromStdString(address.name);
                if (std::holds_alternative<WitnessV2Taproot>(address.dest)) {
                    label += " [PQ]";  // Post-Quantum badge
                }

                cachedAddressTable.append(AddressTableEntry(addressType,
                                  label,
                                  QString::fromStdString(EncodeDestination(address.dest))));
            }
        }
        // std::lower_bound() and std::upper_bound() require our cachedAddressTable list to be sorted in asc order
        // Even though the map is already sorted this re-sorting step is needed because the originating map
        // is sorted by binary address, not by base58() address.
        std::sort(cachedAddressTable.begin(), cachedAddressTable.end(), AddressTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, bool isMine, wallet::AddressPurpose purpose, int status)
    {
        // Find address / label in model
        QList<AddressTableEntry>::iterator lower = std::lower_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        QList<AddressTableEntry>::iterator upper = std::upper_bound(
            cachedAddressTable.begin(), cachedAddressTable.end(), address, AddressTableEntryLessThan());
        int lowerIndex = (lower - cachedAddressTable.begin());
        int upperIndex = (upper - cachedAddressTable.begin());
        bool inModel = (lower != upper);
        AddressTableEntry::Type newEntryType = translateTransactionType(purpose, isMine);
        const CTxDestination dest = DecodeDestination(address.toStdString());
        const bool showEntry = shouldShowAddress(dest, label.toStdString(), purpose);

        if (!showEntry) {
            if (inModel) {
                parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex - 1);
                cachedAddressTable.erase(lower, upper);
                parent->endRemoveRows();
            }
            return;
        }

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_NEW, but entry is already in model";
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
                cachedAddressTable.insert(lowerIndex, AddressTableEntry(newEntryType, label, address));
                parent->endInsertRows();
                break;
            }
            lower->type = newEntryType;
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "AddressTablePriv::updateEntry: Warning: Got CT_DELETED, but entry is not in model";
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedAddressTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedAddressTable.size();
    }

    AddressTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedAddressTable.size())
        {
            return &cachedAddressTable[idx];
        }
        else
        {
            return nullptr;
        }
    }
};

AddressTableModel::AddressTableModel(WalletModel *parent, bool pk_hash_only) :
    QAbstractTableModel(parent), walletModel(parent)
{
    columns << tr("Label") << tr("Address") << tr("Type");
    priv = new AddressTablePriv(this, pk_hash_only);
    priv->refreshAddressTable(parent->wallet());
}

AddressTableModel::~AddressTableModel()
{
    delete priv;
}

int AddressTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return priv->size();
}

int AddressTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return columns.length();
}

QVariant AddressTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    const auto column = static_cast<ColumnIndex>(index.column());
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        switch (column) {
        case Label:
            if (rec->label.isEmpty() && role == Qt::DisplayRole) {
                return tr("(no label)");
            } else {
                return rec->label;
            }
        case Address:
            return rec->address;
        case AddressType:
            return getAddressType(rec->address);
        } // no default case, so the compiler can warn about missing cases
        assert(false);
    } else if (role == Qt::FontRole) {
        switch (column) {
        case Label:
            return QFont();
        case Address:
            return GUIUtil::fixedPitchFont();
        case AddressType:
            return QFont();
        } // no default case, so the compiler can warn about missing cases
        assert(false);
    } else if (role == Qt::ForegroundRole) {
        // Color code by address type
        if (column == AddressType) {
            QString addrType = getAddressType(rec->address);
            if (addrType == tr("Post-Quantum")) {
                return QColor(76, 175, 80);  // Green (#4CAF50)
            } else if (addrType == tr("Taproot")) {
                return QColor(33, 150, 243);  // Blue (#2196F3)
            } else if (addrType == tr("SegWit")) {
                return QColor(255, 152, 0);   // Orange (#FF9800)
            } else if (addrType == tr("Legacy") || addrType == tr("P2SH")) {
                return QColor(158, 158, 158); // Gray (#9E9E9E)
            }
        }
        return QVariant();
    } else if (role == TypeRole) {
        switch(rec->type)
        {
        case AddressTableEntry::Sending:
            return Send;
        case AddressTableEntry::Receiving:
            return Receive;
        case AddressTableEntry::Hidden:
            return {};
        } // no default case, so the compiler can warn about missing cases
        assert(false);
    }
    return QVariant();
}

bool AddressTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if(!index.isValid())
        return false;
    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());
    wallet::AddressPurpose purpose = rec->type == AddressTableEntry::Sending ? wallet::AddressPurpose::SEND : wallet::AddressPurpose::RECEIVE;
    editStatus = OK;

    if(role == Qt::EditRole)
    {
        CTxDestination curAddress = DecodeDestination(rec->address.toStdString());
        if(index.column() == Label)
        {
            // Do nothing, if old label == new label
            if(rec->label == value.toString())
            {
                editStatus = NO_CHANGES;
                return false;
            }
            walletModel->wallet().setAddressBook(curAddress, value.toString().toStdString(), purpose);
        } else if(index.column() == Address) {
            CTxDestination newAddress = DecodeDestination(value.toString().toStdString());
            // Refuse to set invalid address, set error status and return false
            if(std::get_if<CNoDestination>(&newAddress))
            {
                editStatus = INVALID_ADDRESS;
                return false;
            }
            // Do nothing, if old address == new address
            else if(newAddress == curAddress)
            {
                editStatus = NO_CHANGES;
                return false;
            }
            // Check for duplicate addresses to prevent accidental deletion of addresses, if you try
            // to paste an existing address over another address (with a different label)
            if (walletModel->wallet().getAddress(
                    newAddress, /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
            {
                editStatus = DUPLICATE_ADDRESS;
                return false;
            }
            // Double-check that we're not overwriting a receiving address
            else if(rec->type == AddressTableEntry::Sending)
            {
                // Remove old entry
                walletModel->wallet().delAddressBook(curAddress);
                // Add new entry with new address
                walletModel->wallet().setAddressBook(newAddress, value.toString().toStdString(), purpose);
            }
        }
        return true;
    }
    return false;
}

QVariant AddressTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole && section < columns.size())
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags AddressTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid()) return Qt::NoItemFlags;

    AddressTableEntry *rec = static_cast<AddressTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(rec->type == AddressTableEntry::Sending ||
      (rec->type == AddressTableEntry::Receiving && index.column()==Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex AddressTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    AddressTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void AddressTableModel::updateEntry(const QString &address,
        const QString &label, bool isMine, wallet::AddressPurpose purpose, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, isMine, purpose, status);
}

QString AddressTableModel::addRow(const QString &type, const QString &label, const QString &address, const OutputType address_type)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(!walletModel->validateAddress(address))
        {
            editStatus = INVALID_ADDRESS;
            return QString();
        }
        // Check for duplicate addresses
        {
            if (walletModel->wallet().getAddress(
                    DecodeDestination(strAddress), /* name= */ nullptr, /* is_mine= */ nullptr, /* purpose= */ nullptr))
            {
                editStatus = DUPLICATE_ADDRESS;
                return QString();
            }
        }

        // Add entry
        walletModel->wallet().setAddressBook(DecodeDestination(strAddress), strLabel, wallet::AddressPurpose::SEND);
    }
    else if(type == Receive)
    {
        // Generate a new address to associate with given label
        if (auto dest{walletModel->wallet().getNewDestination(address_type, strLabel)}) {
            strAddress = EncodeDestination(*dest);
        } else {
            WalletModel::UnlockContext ctx(walletModel->requestUnlock());
            if (!ctx.isValid()) {
                // Unlock wallet failed or was cancelled
                editStatus = WALLET_UNLOCK_FAILURE;
                return QString();
            }
            if (auto dest_retry{walletModel->wallet().getNewDestination(address_type, strLabel)}) {
                strAddress = EncodeDestination(*dest_retry);
            } else {
                editStatus = KEY_GENERATION_FAILURE;
                return QString();
            }
        }
    }
    else
    {
        return QString();
    }
    return QString::fromStdString(strAddress);
}

bool AddressTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);
    AddressTableEntry *rec = priv->index(row);
    if(count != 1 || !rec || rec->type == AddressTableEntry::Receiving)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }
    walletModel->wallet().delAddressBook(DecodeDestination(rec->address.toStdString()));
    return true;
}

QString AddressTableModel::labelForAddress(const QString &address) const
{
    std::string name;
    if (getAddressData(address, &name, /* purpose= */ nullptr)) {
        return QString::fromStdString(name);
    }
    return QString();
}

std::optional<wallet::AddressPurpose> AddressTableModel::purposeForAddress(const QString &address) const
{
    wallet::AddressPurpose purpose;
    if (getAddressData(address, /* name= */ nullptr, &purpose)) {
        return purpose;
    }
    return std::nullopt;
}

bool AddressTableModel::getAddressData(const QString &address,
        std::string* name,
        wallet::AddressPurpose* purpose) const {
    CTxDestination destination = DecodeDestination(address.toStdString());
    return walletModel->wallet().getAddress(destination, name, /* is_mine= */ nullptr, purpose);
}

int AddressTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

OutputType AddressTableModel::GetDefaultAddressType() const { return walletModel->wallet().getDefaultAddressType(); };

void AddressTableModel::emitDataChanged(int idx)
{
    Q_EMIT dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

QString AddressTableModel::GetWalletDisplayName() const { return walletModel->getDisplayName(); };

QString AddressTableModel::getAddressType(const QString &address) const
{
    CTxDestination dest = DecodeDestination(address.toStdString());

    if (std::holds_alternative<WitnessV2Taproot>(dest)) {
        return tr("Post-Quantum");
    } else if (std::holds_alternative<WitnessV1Taproot>(dest)) {
        return tr("Taproot");
    } else if (std::holds_alternative<WitnessV0KeyHash>(dest) ||
               std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        return tr("SegWit");
    } else if (std::holds_alternative<ScriptHash>(dest)) {
        return tr("P2SH");
    } else if (std::holds_alternative<PKHash>(dest)) {
        return tr("Legacy");
    } else if (std::holds_alternative<WitnessUnknown>(dest)) {
        return tr("Unknown");
    }
    return tr("Invalid");
}
