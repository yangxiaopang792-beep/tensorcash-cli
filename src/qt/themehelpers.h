// Copyright (c) 2024-2026 The TensorCash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_THEMEHELPERS_H
#define BITCOIN_QT_THEMEHELPERS_H

#include <QString>

namespace ThemeHelpers {

// True when the active QPalette is dark (Window lightness < 128).
bool isDarkPalette();

// Stylesheet for a tinted "summary" QGroupBox (e.g. Pricing Breakdown).
// Light theme: subtle gray panel. Dark theme: slightly lighter-than-window panel.
QString panelStyleSheet();

// Stylesheets for status / callout panels (QLabel or QFrame backgrounds).
// All preserve a soft tint in light theme and shift to a darker tint with
// readable foreground text in dark theme.
QString infoPanelStyleSheet();     // was #e3f2fd
QString warningPanelStyleSheet();  // was #fff3e0 / #fffde7 / #fff3cd
QString successPanelStyleSheet();  // was #e8f5e9
QString errorPanelStyleSheet();    // was #ffebee

// Accent text (primary blue): light=#1976d2, dark=#64b5f6.
QString accentTextColor();

// Muted secondary text: light=#666666, dark=#9e9e9e.
QString mutedTextColor();

// Convenience: "QLabel { color: <accent>; }" style snippet, optionally bold.
QString accentLabelStyleSheet(bool bold = false);

// Convenience: "QLabel { color: <muted>; }" style snippet.
QString mutedLabelStyleSheet();

} // namespace ThemeHelpers

#endif // BITCOIN_QT_THEMEHELPERS_H
