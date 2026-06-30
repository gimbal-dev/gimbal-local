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

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 1120, minHeight: 760)
                .task {
                    await model.bootstrap()
                }
        }
        .commands {
            CommandMenu("Gimbal") {
                Button("Refresh") {
                    Task { await model.refreshAll() }
                }
                .keyboardShortcut("r")

                Button("Start Local Daemon") {
                    model.startDaemon()
                }
                .keyboardShortcut("d")
            }
        }
    }
}
