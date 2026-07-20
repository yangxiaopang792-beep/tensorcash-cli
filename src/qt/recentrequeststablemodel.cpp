// Copyright (c) 2024-2025 The TensorCash Core developers
// Copyright (c) 2011-2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/recentrequeststablemodel.h>

#include <qt/bitcoinunits.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/walletmodel.h>

#include <clientversion.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <streams.h>
#include <util/string.h>

#include <utility>

#include <QLatin1Char>
#include <QLatin1String>

using util::ToString;

RecentRequestsTableModel::RecentRequestsTableModel(WalletModel *parent) :
    QAbstractTableModel(parent), walletModel(parent)
{
    // Load entries from wallet
    for (const std::string& request : parent->wallet().getAddressReceiveRequests()) {
        addNewRequest(request);
    }

    /* These columns must match the indices in the ColumnIndex enumeration */
    columns << tr("Date") << tr("Label") << tr("Message") << tr("Asset") << getAmountTitle();

    connect(walletModel->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &RecentRequestsTableModel::updateDisplayUnit);
}

RecentRequestsTableModel::~RecentRequestsTableModel() = default;

int RecentRequestsTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return list.length();
}

int RecentRequestsTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return columns.length();
}

QVariant RecentRequestsTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid() || index.row() >= list.length())
        return QVariant();

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        const RecentRequestEntry *rec = &list[index.row()];
        switch(index.column())
        {
        case Date:
            return GUIUtil::dateTimeStr(rec->date);
        case Label:
            if(rec->recipient.label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->recipient.label;
            }
        case Message:
            if(rec->recipient.message.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no message)");
            }
            else
            {
                return rec->recipient.message;
            }
        case Asset:
            if (rec->recipient.asset_id.has_value()) {
                if (!rec->recipient.asset_ticker.isEmpty()) {
                    return rec->recipient.asset_ticker;
                } else {
                    // Use first 8 chars of asset ID as fallback
                    QString shortId = QString::fromStdString(rec->recipient.asset_id->ToString()).left(8);
                    return QString(shortId + "...");
                }
            } else {
                return "TSC";
            }
            break;
        case Amount:
            if (rec->recipient.asset_id.has_value()) {
                if (rec->recipient.asset_units == 0 && role == Qt::DisplayRole) {
                    return tr("(no amount requested)");
                }

                QString amountBase = GUIUtil::formatAssetAmount(rec->recipient.asset_units, rec->recipient.asset_decimals);
                if (amountBase.isEmpty()) {
                    amountBase = QStringLiteral("0");
                }

                if (role == Qt::DisplayRole) {
                    QString ticker = rec->recipient.asset_ticker;
                    if (ticker.isEmpty() && rec->recipient.asset_id.has_value()) {
                        ticker = QString::fromStdString(rec->recipient.asset_id->ToString()).left(8) + "...";
                    }
                    return QStringLiteral("%1 %2").arg(amountBase, ticker);
                }

                return QVariant(amountBase);
            } else {
                // For BTC, use standard formatting
                if (rec->recipient.amount == 0 && role == Qt::DisplayRole)
                    return tr("(no amount requested)");
                else if (role == Qt::EditRole)
                    return BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), rec->recipient.amount, false, BitcoinUnits::SeparatorStyle::NEVER);
                else
                    return BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), rec->recipient.amount);
            }
        }
    }
    else if (role == Qt::TextAlignmentRole)
    {
        if (index.column() == Amount)
            return (int)(Qt::AlignRight|Qt::AlignVCenter);
    }
    return QVariant();
}

bool RecentRequestsTableModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    return true;
}

QVariant RecentRequestsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

/** Updates the column title to "Amount (DisplayUnit)" and emits headerDataChanged() signal for table headers to react. */
void RecentRequestsTableModel::updateAmountColumnTitle()
{
    columns[Amount] = getAmountTitle();
    Q_EMIT headerDataChanged(Qt::Horizontal,Amount,Amount);
}

/** Gets title for amount column including current display unit if optionsModel reference available. */
QString RecentRequestsTableModel::getAmountTitle()
{
    if (!walletModel->getOptionsModel()) return {};
    return tr("Requested") +
           QLatin1String(" (") +
           BitcoinUnits::shortName(this->walletModel->getOptionsModel()->getDisplayUnit()) +
           QLatin1Char(')');
}

QModelIndex RecentRequestsTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);

    return createIndex(row, column);
}

bool RecentRequestsTableModel::removeRows(int row, int count, const QModelIndex &parent)
{
    Q_UNUSED(parent);

    if(count > 0 && row >= 0 && (row+count) <= list.size())
    {
        for (int i = 0; i < count; ++i)
        {
            const RecentRequestEntry* rec = &list[row+i];
            if (!walletModel->wallet().setAddressReceiveRequest(DecodeDestination(rec->recipient.address.toStdString()), ToString(rec->id), ""))
                return false;
        }

        beginRemoveRows(parent, row, row + count - 1);
        list.erase(list.begin() + row, list.begin() + row + count);
        endRemoveRows();
        return true;
    } else {
        return false;
    }
}

Qt::ItemFlags RecentRequestsTableModel::flags(const QModelIndex &index) const
{
    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

// called when adding a request from the GUI
void RecentRequestsTableModel::addNewRequest(const SendCoinsRecipient &recipient)
{
    RecentRequestEntry newEntry;
    newEntry.id = ++nReceiveRequestsMaxId;
    newEntry.date = QDateTime::currentDateTime();
    newEntry.recipient = recipient;

    DataStream ss{};
    ss << newEntry;

    if (!walletModel->wallet().setAddressReceiveRequest(DecodeDestination(recipient.address.toStdString()), ToString(newEntry.id), ss.str()))
        return;

    addNewRequest(newEntry);
}

// called from ctor when loading from wallet
void RecentRequestsTableModel::addNewRequest(const std::string &recipient)
{
    std::vector<uint8_t> data(recipient.begin(), recipient.end());
    DataStream ss{data};

    RecentRequestEntry entry;
    ss >> entry;

    if (entry.id == 0) // should not happen
        return;

    if (entry.id > nReceiveRequestsMaxId)
        nReceiveRequestsMaxId = entry.id;

    addNewRequest(entry);
}

// actually add to table in GUI
void RecentRequestsTableModel::addNewRequest(RecentRequestEntry &recipient)
{
    beginInsertRows(QModelIndex(), 0, 0);
    list.prepend(recipient);
    endInsertRows();
}

void RecentRequestsTableModel::sort(int column, Qt::SortOrder order)
{
    std::sort(list.begin(), list.end(), RecentRequestEntryLessThan(column, order));
    Q_EMIT dataChanged(index(0, 0, QModelIndex()), index(list.size() - 1, NUMBER_OF_COLUMNS - 1, QModelIndex()));
}

void RecentRequestsTableModel::updateDisplayUnit()
{
    updateAmountColumnTitle();
}

bool RecentRequestEntryLessThan::operator()(const RecentRequestEntry& left, const RecentRequestEntry& right) const
{
    const RecentRequestEntry* pLeft = &left;
    const RecentRequestEntry* pRight = &right;
    if (order == Qt::DescendingOrder)
        std::swap(pLeft, pRight);

    switch(column)
    {
    case RecentRequestsTableModel::Date:
        return pLeft->date.toSecsSinceEpoch() < pRight->date.toSecsSinceEpoch();
    case RecentRequestsTableModel::Label:
        return pLeft->recipient.label < pRight->recipient.label;
    case RecentRequestsTableModel::Message:
        return pLeft->recipient.message < pRight->recipient.message;
    case RecentRequestsTableModel::Asset:
        {
            QString leftAsset = pLeft->recipient.asset_ticker.isEmpty() ?
                (pLeft->recipient.asset_id.has_value() ?
                    QString::fromStdString(pLeft->recipient.asset_id->ToString()) : "TSC") :
                pLeft->recipient.asset_ticker;
            QString rightAsset = pRight->recipient.asset_ticker.isEmpty() ?
                (pRight->recipient.asset_id.has_value() ?
                    QString::fromStdString(pRight->recipient.asset_id->ToString()) : "TSC") :
                pRight->recipient.asset_ticker;
            return leftAsset < rightAsset;
        }
    case RecentRequestsTableModel::Amount:
        if (pLeft->recipient.asset_id.has_value() && pRight->recipient.asset_id.has_value()) {
            return pLeft->recipient.asset_units < pRight->recipient.asset_units;
        } else {
            return pLeft->recipient.amount < pRight->recipient.amount;
        }
    default:
        return pLeft->id < pRight->id;
    }
}
