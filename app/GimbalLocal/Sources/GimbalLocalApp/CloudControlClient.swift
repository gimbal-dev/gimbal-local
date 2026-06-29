// Copyright © 2024 Cloud Hypervisor contributors
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

import Foundation

struct CloudControlClient {
    func overview(baseURL: String) async -> CloudOverview {
        guard let root = URL(string: baseURL.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            return CloudOverview(
                state: .offline("invalid control-plane URL"),
                runners: nil,
                snapshots: nil,
                sandboxes: nil,
                costSummary: nil
            )
        }

        do {
            _ = try await data(from: root.appending(path: "healthz"))
            async let runners = countItems(at: root.appending(path: "runners"))
            async let snapshots = countItems(at: root.appending(path: "snapshots"))
            async let sandboxes = countItems(at: root.appending(path: "sandboxes"))
            async let cost = costSummary(at: root.appending(path: "cost/running"))

            return CloudOverview(
                state: .online,
                runners: await runners,
                snapshots: await snapshots,
                sandboxes: await sandboxes,
                costSummary: await cost
            )
        } catch {
            return CloudOverview(
                state: .offline(error.localizedDescription),
                runners: nil,
                snapshots: nil,
                sandboxes: nil,
                costSummary: nil
            )
        }
    }

    private func countItems(at url: URL) async -> Int? {
        do {
            let payload = try await data(from: url)
            return Self.countItems(in: payload)
        } catch {
            return nil
        }
    }

    private func costSummary(at url: URL) async -> String? {
        do {
            let payload = try await data(from: url)
            return Self.shortSummary(from: payload)
        } catch {
            return nil
        }
    }

    private func data(from url: URL) async throws -> Data {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return data
    }

    static func countItems(in data: Data) -> Int? {
        guard let json = try? JSONSerialization.jsonObject(with: data) else {
            return nil
        }
        if let array = json as? [Any] {
            return array.count
        }
        guard let object = json as? [String: Any] else {
            return nil
        }
        for key in ["items", "runners", "snapshots", "sandboxes", "resources", "leases", "operations"] {
            if let array = object[key] as? [Any] {
                return array.count
            }
        }
        return nil
    }

    static func shortSummary(from data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) else {
            return nil
        }
        if let object = json as? [String: Any] {
            if let warning = object["warning"] as? String, !warning.isEmpty {
                return warning
            }
            if let total = object["estimated_hourly_cost"] ?? object["estimatedHourlyCost"] {
                return "estimated hourly cost: \(total)"
            }
            if let resources = object["resources"] as? [Any] {
                return "\(resources.count) running cloud resource(s)"
            }
        }
        return "cost view available"
    }
}
