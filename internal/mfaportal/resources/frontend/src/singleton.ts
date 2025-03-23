import type { App } from "vue";

export class SingleInstanceManager {
    private channel: BroadcastChannel;
    private instanceId: string;
    private vueApplication: App;

    constructor(app: App, channelName: string = 'wag-single-instance') {
        this.instanceId = crypto.randomUUID()
        this.channel = new BroadcastChannel(channelName);
        this.vueApplication = app;

        // Set up event listeners
        this.channel.onmessage = this.handleMessage.bind(this);
        window.addEventListener('beforeunload', () => {
            this.channel.close();
        });
    }

    public initialize(): void {
        // Announce this instance
        this.sendMessage('instance-active');
    }

    private handleMessage(event: MessageEvent): void {
        const { type, id } = event.data;

        // Another instance is active, close this one
        if (id === this.instanceId) {
            return
        }

        switch (type) {
            case 'instance-active':
                this.channel.close();
                this.vueApplication.unmount()
                document.body.innerHTML = '<div>Application is running in another tab. Please reload this page, or use that instance.</div>'
                break;
            default:
                console.log("unknown broadcast event ", type, "ignoring")
                break;

        }
    }

    private sendMessage(type: string): void {
        this.channel.postMessage({
            type,
            id: this.instanceId
        });
    }
}