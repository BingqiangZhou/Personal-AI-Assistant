import WidgetKit
import SwiftUI

@main
struct StellaWidgetBundle: WidgetBundle {
    var body: some Widget {
        NowPlayingWidget()
        RecentUpdatesWidget()
    }
}
