// Copyright (c) 2024-2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/themehelpers.h>

#include <QApplication>
#include <QPalette>

namespace ThemeHelpers {

bool isDarkPalette()
{
    if (QApplication* app = qobject_cast<QApplication*>(QCoreApplication::instance())) {
        return app->palette().color(QPalette::Window).lightness() < 128;
    }
    return false;
}

QString panelStyleSheet()
{
    if (isDarkPalette()) {
        return QStringLiteral(
            "QGroupBox { font-weight: bold; background-color: #2d2d2d; "
            "border: 1px solid #555; border-radius: 4px; "
            "margin-top: 8px; padding-top: 8px; }");
    }
    return QStringLiteral(
        "QGroupBox { font-weight: bold; background-color: #f5f5f5; "
        "border: 1px solid #ccc; border-radius: 4px; "
        "margin-top: 8px; padding-top: 8px; }");
}

QString infoPanelStyleSheet()
{
    if (isDarkPalette()) {
        return QStringLiteral(
            "background-color: #1e3a5f; color: #bbdefb; "
            "border-radius: 4px; padding: 8px;");
    }
    return QStringLiteral(
        "background-color: #e3f2fd; color: #0d47a1; "
        "border-radius: 4px; padding: 8px;");
}

QString warningPanelStyleSheet()
{
    if (isDarkPalette()) {
        return QStringLiteral(
            "background-color: #4a3a1a; color: #ffe082; "
            "border-radius: 4px; padding: 8px;");
    }
    return QStringLiteral(
        "background-color: #fff3e0; color: #6d4c00; "
        "border-radius: 4px; padding: 8px;");
}

QString successPanelStyleSheet()
{
    if (isDarkPalette()) {
        return QStringLiteral(
            "background-color: #1f3a23; color: #a5d6a7; "
            "border-radius: 4px; padding: 8px;");
    }
    return QStringLiteral(
        "background-color: #e8f5e9; color: #1b5e20; "
        "border-radius: 4px; padding: 8px;");
}

QString errorPanelStyleSheet()
{
    if (isDarkPalette()) {
        return QStringLiteral(
            "background-color: #4a1f1f; color: #ef9a9a; "
            "border-radius: 4px; padding: 8px;");
    }
    return QStringLiteral(
        "background-color: #ffebee; color: #b71c1c; "
        "border-radius: 4px; padding: 8px;");
}

QString accentTextColor()
{
    return isDarkPalette() ? QStringLiteral("#64b5f6") : QStringLiteral("#1976d2");
}

QString mutedTextColor()
{
    return isDarkPalette() ? QStringLiteral("#9e9e9e") : QStringLiteral("#666666");
}

QString accentLabelStyleSheet(bool bold)
{
    return QStringLiteral("QLabel { color: %1; font-weight: %2; }")
        .arg(accentTextColor(), bold ? QStringLiteral("bold") : QStringLiteral("normal"));
}

QString mutedLabelStyleSheet()
{
    return QStringLiteral("QLabel { color: %1; }").arg(mutedTextColor());
}

} // namespace ThemeHelpers
