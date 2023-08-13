import SwiftUI

struct ContentView: View {
    @State private var kfd: UInt64 = 0
    
    @State private var puafPages = 2048
    @State private var puafMethod = 1
    @State private var kreadMethod = 1
    @State private var kwriteMethod = 1
    //tweak vars
    @State private var enableHideDock = false
    @State private var enableCCTweaks = false
    @State private var enableLSTweaks = false
    @State private var enableCustomFont = false
    @State private var enableResSet = false
    @State private var enableHideHomebar = false
    @State private var enableHideNotifs = false
    @State private var enablePasscodes = false
    @State private var enableDynamicIsland = false
    
    var puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    var puafMethodOptions = ["physpuppet", "smith"]
    var kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open"]
    var kwriteMethodOptions = ["dup", "sem_open"]
    
    @State private var isSettingsPopoverPresented = false // Track the visibility of the settings popup
    
    var body: some View {
        NavigationView {
            List {
                
            
                if kfd != 0 {
                    Section(header: Text("Status")) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Success!")
                                .font(.headline)
                                .foregroundColor(.green)
                            Text("Tap umbrella to respring <3")
                                .foregroundColor(.pink)
                        }
                    }
                }
                
                Section(header: Text("Tweaks")) {
                    VStack(alignment: .leading, spacing: 20) {
                        Toggle(isOn: $enableHideDock) {
                            HStack(spacing: 20) {
                                Image(systemName: enableHideDock ? "eye.slash" : "eye")
                                    .foregroundColor(.blue)
                                    .imageScale(.large)
                                Text("Hide Dock")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableHideDock, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })

                        Toggle(isOn: $enableHideHomebar) {
                            HStack(spacing: 20) {
                                Image(systemName: enableHideHomebar ? "rectangle.grid.1x2.fill" : "rectangle.grid.1x2")
                                    .foregroundColor(.purple)
                                    .imageScale(.large)
                                Text("Hide Home Bar")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableHideHomebar, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })

                        Toggle(isOn: $enableResSet) {
                            HStack(spacing: 20) {
                                Image(systemName: enableResSet ? "arrow.up.circle.fill" : "arrow.down.circle.fill")
                                    .foregroundColor(.green)
                                    .imageScale(.large)
                                Text("Enable iPhone 14 Pro Resolution")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableResSet, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })

                        Toggle(isOn: $enableCustomFont) {
                            HStack(spacing: 20) {
                                Image(systemName: enableCustomFont ? "a.circle.fill" : "a.circle")
                                    .foregroundColor(.orange)
                                    .imageScale(.large)
                                Text("Enable Custom Font")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableCustomFont, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })

                        Toggle(isOn: $enableCCTweaks) {
                            HStack(spacing: 20) {
                                Image(systemName: enableCCTweaks ? "pencil.circle.fill" : "pencil.circle")
                                    .foregroundColor(.pink)
                                    .imageScale(.large)
                                Text("Enable CC Custom Icons")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableCCTweaks, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })
                        Toggle(isOn: $enableLSTweaks) {
                            HStack(spacing: 20) {
                                Image(systemName: enableLSTweaks ? "pencil.circle.fill" : "pencil.circle")
                                    .foregroundColor(.pink)
                                    .imageScale(.large)
                                Text("Enable Lockscreen Custom Icons")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableLSTweaks, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })
                        Toggle(isOn: $enableHideNotifs) {
                            HStack(spacing: 20) {
                                Image(systemName: enableHideNotifs ? "pencil.circle.fill" : "pencil.circle")
                                    .foregroundColor(.pink)
                                    .imageScale(.large)
                                Text("Enable hiding notification and media player background")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableHideNotifs, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })
                        Toggle(isOn: $enablePasscodes) {
                            HStack(spacing: 20) {
                                Image(systemName: enablePasscodes ? "pencil.circle.fill" : "pencil.circle")
                                    .foregroundColor(.pink)
                                    .imageScale(.large)
                                Text("Enable theming passcode icons")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enablePasscodes, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })
                        Toggle(isOn: $enableDynamicIsland) {
                            HStack(spacing: 20) {
                                Image(systemName: enableDynamicIsland ? "pencil.circle.fill" : "pencil.circle")
                                    .foregroundColor(.pink)
                                    .imageScale(.large)
                                Text("Enable dynamic island")
                                    .font(.headline)
                            }
                        }
                        .onChange(of: enableDynamicIsland, perform: { _ in
                            // Perform any actions when the toggle state changes
                        })
                    }
                    .padding(.vertical, 8)
                }

                Section(header: Text("Confirm")) {
                    Button("Confirm") {
                        kfd = do_kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                        let tweaks = enabledTweaks()

                        // Convert the Swift array of strings to a C-style array of char*
                        var cTweaks: [UnsafeMutablePointer<CChar>?] = tweaks.map { strdup($0) }
                        // Add a null pointer at the end to signal the end of the array
                        cTweaks.append(nil)

                        // Pass the C-style array to do_fun along with the count of tweaks
                        cTweaks.withUnsafeMutableBufferPointer { buffer in
                            do_fun(buffer.baseAddress, Int32(buffer.count - 1))
                        }

//                         Deallocate the C-style strings after use to avoid memory leaks
                        cTweaks.forEach { free($0) }
//                        restartBackboard()
                        do_kclose()
                    }
                    .buttonStyle(BorderlessButtonStyle())
                }
                
            }
            .navigationBarTitle("kfdtweaks", displayMode: .inline)
            .accentColor(.green) // Highlight the navigation bar elements in green
            .navigationBarItems(leading: respringButton, trailing: settingsButton)
            .popover(isPresented: $isSettingsPopoverPresented, arrowEdge: .bottom) {
                settingsPopover
            }
        }
    }
    
    // Settings Button in the Navigation Bar
    private var settingsButton: some View {
        Button(action: {
            isSettingsPopoverPresented.toggle()
        }) {
            Image(systemName: "gearshape")
                .imageScale(.large)
                .foregroundColor(.green)
        }
    }
    
    private var respringButton: some View {
        Button(action: {
            restartFrontboard()
        }) {
            Image(systemName: "umbrella")
                .imageScale(.large)
                .foregroundColor(.green)
        }
    }
    
    // Payload Settings Popover
    private var settingsPopover: some View {
        VStack {
            Section(header: Text("Payload Settings")) {
                Picker("puaf pages:", selection: $puafPages) {
                    ForEach(puafPagesOptions, id: \.self) { pages in
                        Text(String(pages))
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
                
                Picker("puaf method:", selection: $puafMethod) {
                    ForEach(0..<puafMethodOptions.count, id: \.self) { index in
                        Text(puafMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
            }
            
            Section(header: Text("Kernel Settings")) {
                Picker("kread method:", selection: $kreadMethod) {
                    ForEach(0..<kreadMethodOptions.count, id: \.self) { index in
                        Text(kreadMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
                
                Picker("kwrite method:", selection: $kwriteMethod) {
                    ForEach(0..<kwriteMethodOptions.count, id: \.self) { index in
                        Text(kwriteMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
            }
            
            Button("Apply Settings") {
                isSettingsPopoverPresented = false
            }
        }
        .padding()
    }
    
    private func enabledTweaks() -> [String] {
        var enabledTweaks: [String] = []
        if enableHideDock {
            enabledTweaks.append("HideDock")
        }
        if enableHideHomebar {
            enabledTweaks.append("enableHideHomebar")
        }
        if enableResSet {
            enabledTweaks.append("enableResSet")
        }
        if enableCustomFont {
            enabledTweaks.append("enableCustomFont")
        }
        if enableCCTweaks {
            enabledTweaks.append("enableCCTweaks")
        }
        if enableLSTweaks {
            enabledTweaks.append("enableLSTweaks")
        }
        if enableHideNotifs {
            enabledTweaks.append("enableHideNotifs")
        }
        if enablePasscodes {
            enabledTweaks.append("enablePasscodes")
        }
        if enableDynamicIsland {
            enabledTweaks.append("enableDynamicIsland")
        }

        return enabledTweaks
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
