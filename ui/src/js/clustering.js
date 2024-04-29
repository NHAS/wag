class AddNode extends HTMLElement {

    constructor() {
        // Always call super first in constructor
        super();
    }

    connectedCallback() {
        this.inputForm = this.querySelector("#inputForm")
        this.resultForm = this.querySelector("#result")

        this.inputForm.addEventListener("transitionend", (e) => {
            if (e.target === this.inputForm) {
                this.inputForm.hidden = true
                this.resultForm.hidden = false
                this.resultForm.classList.add("show")
            }
        })


        this.newNodeName = this.querySelector("#newNodeName")
        this.nodeURL = this.querySelector("#nodeURL")
        this.managerURL = this.querySelector("#managerURL")

        this.addBtn = this.querySelector("#add")
        this.addBtn.addEventListener("click", () => this.submitNode())

        $("#clusterAddModal").on('hidden.bs.modal', () => {
            this.inputForm.hidden = false
            this.resultForm.hidden = true

            this.inputForm.classList.remove("fade")
            this.resultForm.classList.remove("show")

            this.newNodeName.value = ""
            this.nodeURL.value = ""
            this.managerURL.value = ""

            window.location.reload()
        });


        this.joinToken = this.querySelector("#joinToken")
        this.copyJoinToken = this.querySelector("#btn-copy-token")
        this.copyJoinToken.addEventListener("click", () => {
            navigator.clipboard.writeText(this.joinToken.textContent);
            Toastify({
                text: "Copied!",
                position: "right",
                gravity: "bottom",
                style: {
                    background: "#0bb329",
                }
            }).showToast();
        })

        this.csrfToken = document.querySelector("#csrf_token").value

    }

    async submitNode() {
        let data = {
            "ConnectionURL": this.nodeURL.value,
            "NodeName": this.newNodeName.value,
            "ManagerURL": this.managerURL.value,
        }

        try {
            let res = await fetch("/cluster/members/new", {
                method: "POST",
                body: JSON.stringify(data),
                headers: {
                    "Content-Type": "application/json",
                    "WAG-CSRF": this.csrfToken,
                }
            })

            if (res.status !== 200) {
                let errText = await res.text()
                Toastify({
                    text: errText,
                    position: "right",
                    gravity: "top",
                    offset: {
                        y: 60,
                        x: 10,
                    },
                    stopOnFocus: true,
                    style: {
                        background: "#db0b3c",
                    }
                }).showToast();
                console.log("failed: ", errText)
                return
            }

            let obj = await res.json()

            this.joinToken.textContent = obj.JoinToken;
            this.inputForm.classList.add("fade")


        } catch (err) {
            console.log("failed: ", err)
            Toastify({
                text: err,
                position: "right",
                gravity: "top",
                offset: {
                    y: 60,
                    x: 10,
                },
                stopOnFocus: true,
                style: {
                    background: "#db0b3c",
                }
            }).showToast();
        }
    }
}


class NodeControls extends HTMLElement {

    constructor() {
        // Always call super first in constructor
        super();
    }

    connectedCallback() {
        this.promteBtn = this.querySelector("#promote")
        this.drainBtn = this.querySelector("#drain")
        this.removeBtn = this.parentNode.querySelector("#remove")

        this.csrfToken = document.querySelector("#csrf_token").value
        this.ourNode = this.getAttribute("node")

        if (this.promteBtn) {
            this.promteBtn.addEventListener("click", () => this.nodeAction("promote"))
        }

        if (this.removeBtn) {
            this.removeBtn.addEventListener("click", () => this.nodeAction("remove"))
        }
        this.drainBtn.addEventListener("click", (e) => this.nodeAction(e.target.getAttribute("action")))
    }



    async nodeAction(action) {
        let data = {
            "Action": action,
            "Node": this.ourNode,
        }

        try {
            let res = await fetch("/cluster/members/control", {
                method: "POST",
                body: JSON.stringify(data),
                headers: {
                    "Content-Type": "application/json",
                    "WAG-CSRF": this.csrfToken,
                }
            })

            if (res.status !== 200) {
                let errText = await res.text()
                console.log("failed: ", errText)
                Toastify({
                    text: errText,
                    position: "right",
                    gravity: "top",
                    offset: {
                        y: 60,
                        x: 10,
                    },
                    stopOnFocus: true,
                    style: {
                        background: "#db0b3c",
                    }
                }).showToast();
                return
            }

            window.location.reload();

        } catch (err) {
            console.log("error acting on node: ", err)
            Toastify({
                text: err,
                position: "right",
                gravity: "top",
                offset: {
                    y: 60,
                    x: 10,
                },
                stopOnFocus: true,
                style: {
                    background: "#db0b3c",
                }
            }).showToast();
        }
    }


}


customElements.define("add-node", AddNode);
customElements.define("node-control", NodeControls);