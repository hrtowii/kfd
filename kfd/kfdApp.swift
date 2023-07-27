/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

import SwiftUI

@main

struct kfdApp: App {
    @State private var path = ""
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onAppear {
                                    // Get current directory path
                                    self.path = FileManager.default.currentDirectoryPath
                                    print(self.path)
                                }
        }
    }
}
