// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

@main
struct GimbalLocalApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Gimbal Local", id: "main") {
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
