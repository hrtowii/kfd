import SwiftUI

struct ContentView: View {
    @State private var kfd: UInt64 = 0
    
    @State private var puafPages = 2048
    @State private var puafMethod = 1
    @State private var kreadMethod = 2
    @State private var kwriteMethod = 2
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
    private var puaf_method_options = ["physpuppet", "smith"]

    private var kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open", "IOSurface"]

    private var kwriteMethodOptions = ["dup", "sem_open", "IOSurface"]
    
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
                Section(header: Text("Confirm")) {
                    Button("Confirm") {
                        kfd = do_kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                        grant_full_disk_access()
//                        themePasscodes()
//                        do_trolling()
                        do_kclose()
//                        restartFrontboard()
                    }
                    .buttonStyle(BorderlessButtonStyle())
                }
                Section {
                    HStack {
                        Button("stage2") {
                            stage2(kfd)
                        }.disabled(kfd == 0).frame(minWidth: 0, maxWidth: .infinity)
                    }
                }.listRowBackground(Color.clear)
                
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
