// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import SwiftUI

@main
struct GimbalLocalApp: App {
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
