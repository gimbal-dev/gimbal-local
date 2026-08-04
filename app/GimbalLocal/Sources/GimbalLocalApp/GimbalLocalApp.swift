// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI
import AppKit

/// Sets the Dock / app-switcher icon from the bundled `AppIcon.icns`. The
/// bundle's `CFBundleIconFile` already points Finder at the icon, but freshly
/// built bundles can show a stale cached icon until this nudges it at launch.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let image = NSImage(contentsOf: url) {
            NSApplication.shared.applicationIconImage = image
        }
    }
}

@main
struct GimbalLocalApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        Window("Gimbal Local", id: "main") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1120, minHeight: 760)
                .task {
                    await model.bootstrap()
                }
        }
        .onChange(of: scenePhase) { _, phase in
            // Coming back from Finder is exactly when a newly-added image should
            // be there. The scan is one directory listing, so doing it on every
            // activation is cheaper than making the user find a Refresh button
            // to explain why the folder they just filled looks empty.
            if phase == .active {
                model.refreshLocalImages()
            }
        }
        .commands {
            CommandMenu("Gimbal") {
                Button("Refresh") {
                    Task { await model.refreshAll() }
                }
                .keyboardShortcut("r")

                Divider()

                Button("Start Local Engine") {
                    model.startDaemon()
                }
                .keyboardShortcut("d")

                Button("Restart Local Engine") {
                    model.restartDaemon()
                }

                Button("Shut Down Local Engine") {
                    model.shutdownDaemon()
                }
            }
        }

        Settings {
            SettingsView()
                .environmentObject(model)
        }

        MenuBarExtra {
            MenuBarView()
                .environmentObject(model)
        } label: {
            Image(systemName: model.engineIndicator.symbol)
        }
    }
}
