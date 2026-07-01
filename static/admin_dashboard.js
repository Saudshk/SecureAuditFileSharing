const roleSelect = document.getElementById("roleSelect");
const roleTrigger = document.getElementById("roleTrigger");
const roleOptions = document.getElementById("roleOptions");
const roleText = document.getElementById("roleText");
const roleValue = document.getElementById("roleValue");

if (roleSelect && roleTrigger && roleOptions && roleText && roleValue) {
    const roleItems = roleOptions.querySelectorAll(".custom-option");

    roleTrigger.addEventListener("click", function () {
        roleSelect.classList.toggle("open");
    });

    roleItems.forEach(function (item) {
        item.addEventListener("click", function () {
            roleItems.forEach(function (opt) {
                opt.classList.remove("selected");
            });

            this.classList.add("selected");
            roleText.textContent = this.textContent;
            roleValue.value = this.dataset.value;
            roleSelect.classList.remove("open");
        });
    });

    document.addEventListener("click", function (e) {
        if (!roleSelect.contains(e.target)) {
            roleSelect.classList.remove("open");
        }
    });
}