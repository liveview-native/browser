```swift
final class LvnWorkerThread: Thread {
    private var ctx: MyCtx?
    init?(_ url: URL) {
        guard let c = lvn_init(url) else {return nil}
        super.init()
        self.name = "LvnWorkerThread"
        self.qualityOfService = .utility
    }
    
    override func main() {
        autoreleasepool {
            lvn_run(ctx)
        }
    }
    
    deinit {
        lvn_deinit(ctx)
    }
}
```