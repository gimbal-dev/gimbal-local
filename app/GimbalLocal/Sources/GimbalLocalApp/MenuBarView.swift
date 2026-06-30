// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import AppKit
import SwiftUI

/// Contents of the macOS menu bar extra. Lets the app stay useful with the main
/// window closed: it surfaces the most recently active sandboxes plus quick
/// engine and app actions.
struct MenuBarView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let recents = Array(model.recentSandboxes.prefix(3))

        Text("\(model.engineIndicator.label) · \(model.engineIndicator.detail)")

        Divider()

        if recents.isEmpty {
            Text("No sandboxes yet")
        } else {
            Section("Recent sandboxes") {
                ForEach(recents) { snapshot in
                    Button {
                        model.selectedSnapshot = snapshot
                        showMainApp()
                    } label: {
                        Text("\(snapshot.name)  ·  \(snapshot.vcpus) vCPU, \(snapshot.ramMib) MiB")
                    }
                }
            }
        }

        if model.recentSandboxes.count > recents.count {
            Button("See more…") { showMainApp() }
        }

        Divider()

        Button("Open Main App") { showMainApp() }
        Button("Shut Down Engine") { model.shutdownDaemon() }

        Divider()

        Button("Quit Gimbal Local") { NSApplication.shared.terminate(nil) }
    }

    private func showMainApp() {
        openWindow(id: "main")
        NSApplication.shared.activate()
    }
}
