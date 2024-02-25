class AddNode extends HTMLElement {

    constructor() {
        // Always call super first in constructor
        super();
    }

    connectedCallback() {
        this.inputForm = this.querySelector("#inputForm")
        this.resultForm = this.querySelector("#result")

        const inputForm = this.inputForm
        const resultForm = this.resultForm
        this.inputForm.addEventListener("transitionend", function (e) {
            if (e.target === this) {
                inputForm.hidden = true
                resultForm.classList.add("show")
            }
        })


        this.newNodeName = this.querySelector("#newNodeName")
        this.nodeURL = this.querySelector("#nodeURL")
        this.managerURL = this.querySelector("#managerURL")

        this.addBtn = this.querySelector("#add")
        this.addBtn.addEventListener("click", () => this.submitNode())



        this.joinToken = this.querySelector("#joinToken")
        this.copyJoinToken = this.querySelector("#btn-copy-token")
        this.copyJoinToken.addEventListener("click", () => {

        })

        this.csrfToken = document.querySelector("#csrf_token").value

    }

    async submitNode() {
        let data = {
            "NodeName": this.newNodeName.value,
            "ConnectionURL": this.nodeURL.value,
            "ManagerURL": this.managerURL.value,
        }

        try {
            let res = await fetch("/settings/clustering/new-node", {
                method: "POST",
                body: JSON.stringify(data),
                headers: {
                    "Content-Type": "application/json",
                    "WAG-CSRF": this.csrfToken,
                }
            })

            if (res.status !== 200) {
                console.log("failed: ", await res.text())
                return
            }

            let obj = await res.json()

            this.joinToken.textContent = obj.JoinToken;
            this.inputForm.classList.add("fade")


        } catch (err) {

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
        this.removeBtn = this.querySelector("#remove")

        this.csrfToken = document.querySelector("#csrf_token").value
        this.ourNode = this.getAttribute("node")

        this.promteBtn.addEventListener("click", () => this.nodeAction("promote"))
        this.drainBtn.addEventListener("click", () => this.nodeAction("drain"))
        this.removeBtn.addEventListener("click", () => this.nodeAction("remove"))
    }



    async nodeAction(action) {
        let data = {
            "Action": action,
            "Node": this.ourNode,
        }

        try {
            let res = await fetch("/settings/clustering/node-control", {
                method: "POST",
                body: JSON.stringify(data),
                headers: {
                    "Content-Type": "application/json",
                    "WAG-CSRF": this.csrfToken,
                }
            })

            if (res.status !== 200) {
                console.log("failed: ", await res.text())
                return
            }

            window.location.reload();

        } catch (err) {

        }
    }


}


customElements.define("add-node", AddNode);
customElements.define("node-control", NodeControls);