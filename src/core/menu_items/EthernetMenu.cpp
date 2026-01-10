#include "EthernetMenu.h"
#if !defined(LITE_VERSION)
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "modules/ethernet/ARPScanner.h"
#include "modules/ethernet/DHCPStarvation.h"
#include "modules/ethernet/EthernetHelper.h"
#include "modules/ethernet/MACFlooding.h"

void EthernetMenu::start_ethernet() {
    eth = new EthernetHelper();
    if (!eth->setup()) {
        displayError("W5500 not found");
        delete eth;
        eth = nullptr;
        return;
    }
    while (!eth->is_connected()) { delay(100); }
}

void EthernetMenu::optionsMenu() {
    options = {
        {"Scan Hosts",
         [this]() {
             start_ethernet();
             if (eth != nullptr) {
                 run_arp_scanner();
                 eth->stop();
             } else {
                 displayError("W5500 not found");
             }
         }                        },
        {"DHCP Starvation",
         [this]() {
             start_ethernet();
             if (eth != nullptr) {
                 DHCPStarvation();
                 eth->stop();
             } else {
                 displayError("W5500 not found");
             }
         }                        },
        {"MAC Flooding",    [this]() {
             start_ethernet();
             if (eth != nullptr) {
                 MACFlooding();
                 eth->stop();
             } else {
                 displayError("W5500 not found");
             }
         }}
    };
    addOptionToMainMenu();

    delay(200);

    loopOptions(options, MENU_TYPE_SUBMENU, "Ethernet");
}

void EthernetMenu::drawIconImg() {
    drawImg(
        *bruceConfig.themeFS(),
        bruceConfig.getThemeItemImg(bruceConfig.theme.paths.ethernet),
        0,
        imgCenterY,
        true
    );
}
void EthernetMenu::drawIcon(float scale) {
    clearIconArea();

    // Adjusted coordinate calculation for scaling and centering
    int iconW = scale * 30;
    int iconH = scale * 40;

    // Scale dependent offsets
    int Y = iconCenterY - iconH / 2 - 3; // Fixed: center vertically properly (moved up 3px)
    int smallerH = scale * 16;

    int starterX = iconCenterX - iconW; // X of the first side
    int finalX = iconCenterX + iconW;

    int lineWidth = (scale < 0.5) ? 1 : 2; // Thinner lines for small icons

    // Draw the main socket structure
    /*
    |-----|
    |     |
    |     |
    */
    tft.drawRect(starterX, Y, lineWidth, iconH, bruceConfig.priColor);

    tft.drawRect(finalX, Y, lineWidth, iconH, bruceConfig.priColor);

    tft.drawRect(starterX, Y, iconW * 2, lineWidth, bruceConfig.priColor);

    // Draw the shorter side to close the first part of socket
    /*
    |-----|
    |     |
    |-   -|
    */
    tft.drawRect(starterX, Y + iconH, smallerH, lineWidth, bruceConfig.priColor);

    tft.drawRect(finalX - smallerH + lineWidth, Y + iconH, smallerH, lineWidth, bruceConfig.priColor);

    // Draw the final enclosure
    /*
    |------|
    |      |
    |-    -|
      |  |
    */
    tft.drawRect(starterX + smallerH, Y + iconH, lineWidth, smallerH, bruceConfig.priColor);
    tft.drawRect(finalX - smallerH + lineWidth, Y + iconH, lineWidth, smallerH, bruceConfig.priColor);

    // Draw the four cable pin at a distance of 15 pixel
    // Draw pins
    float pinStep = (float)(iconW * 2 - 4) / 4.0;
    for (size_t i = 0; i < 4; i++) {
        // Distribute pins evenly
        int pinX = starterX + 2 + (i * pinStep) + (pinStep / 2) - (lineWidth / 2);
        // Scale pin height
        int pinH = iconH * 0.4;
        tft.drawRect(pinX, Y, lineWidth, pinH, bruceConfig.priColor);
    }

    // Close the socket calculating width of this side removing from total width, the size of the smaller size
    tft.drawRect(
        starterX + smallerH,
        Y + iconH + smallerH,
        (iconW * 2) - (smallerH * 2) + lineWidth * 2,
        lineWidth,
        bruceConfig.priColor
    );
}
#endif
