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
        let sandboxes = Array(model.sandboxes.prefix(4))

        Text("\(model.engineIndicator.label) · \(model.engineIndicator.detail)")

        Divider()

        if sandboxes.isEmpty {
            Text("No sandboxes yet")
        } else {
            Section("Sandboxes") {
                ForEach(sandboxes) { sandbox in
                    Button {
                        model.selection = .sandbox(sandbox.id)
                        showMainApp()
                    } label: {
                        Text("\(sandbox.name)  ·  \(sandbox.state.label)")
                    }
                }
            }
        }

        if model.sandboxes.count > sandboxes.count {
            Button("See all…") {
                model.selection = .sandboxesHome
                showMainApp()
            }
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
