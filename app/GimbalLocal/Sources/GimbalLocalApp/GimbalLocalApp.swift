// Copyright © 2026 Ben De St Paer-Gotch
//
// SPDX-License-Identifier: LicenseRef-Gimbal-Proprietary

import SwiftUI
import AppKit

/// Sets the Dock / app-switcher icon from the bundled `AppIcon.icns`. The
/// bundle's `CFBundleIconFile` already points Finder at the icon, but freshly
/// built bundles can show a stale cached icon until this nudges it at launch.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Set by `GimbalLocalApp` once the model exists. Weak so the delegate does
    /// not keep the model alive past the app.
    weak var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let image = NSImage(contentsOf: url) {
            NSApplication.shared.applicationIconImage = image
        }
    }

    /// Stop the daemon this app started before the app goes away (#360).
    ///
    /// Without this, `chm serve` is reparented to launchd and runs forever,
    /// holding the process-global HVF slot so the next `chm run` fails
    /// `HV_BUSY` with nothing on screen to blame.
    func applicationShouldTerminate(
        _ sender: NSApplication
    ) -> NSApplication.TerminateReply {
        guard let model else { return .terminateNow }

        switch QuitDisposition.decide(
            startedDaemon: model.startedDaemon,
            runningGuests: model.runningGuests
        ) {
        case .nothingToStop:
            return .terminateNow

        case .stopDaemon:
            // The shutdown has to be awaited: quitting before it is delivered
            // is the leak itself, so termination waits rather than racing.
            Task { @MainActor in
                await model.stopDaemonAndWait()
                sender.reply(toApplicationShouldTerminate: true)
            }
            return .terminateLater

        case .confirm(let running):
            let alert = NSAlert()
            alert.messageText = "Quit Gimbal Local?"
            alert.informativeText = QuitDisposition.confirmationMessage(running: running)
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Quit and Stop")
            alert.addButton(withTitle: "Cancel")
            guard alert.runModal() == .alertFirstButtonReturn else {
                return .terminateCancel
            }
            Task { @MainActor in
                await model.stopDaemonAndWait()
                sender.reply(toApplicationShouldTerminate: true)
            }
            return .terminateLater
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
                    appDelegate.model = model
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
