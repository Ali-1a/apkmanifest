document.addEventListener("DOMContentLoaded", () => {
    const fileInput = document.getElementById("apk_file");
    const dropzone = document.getElementById("dropzone");
    const dropzoneContent = document.querySelector(".dropzone-content");
    const dropzoneSelected = document.getElementById("dropzone-selected");
    const selectedName = document.getElementById("selected-name");
    const selectedSize = document.getElementById("selected-size");
    const scanButton = document.getElementById("scan-button");
    const form = document.getElementById("upload-form");

    if (!fileInput || !dropzone || !scanButton) return;

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(2) + " MB";
    }

    function updateUI(file) {
        if (file) {
            if (dropzoneContent) dropzoneContent.style.display = "none";
            if (dropzoneSelected) dropzoneSelected.style.display = "block";
            if (selectedName) selectedName.textContent = file.name;
            if (selectedSize) selectedSize.textContent = formatFileSize(file.size);
            scanButton.disabled = false;
            scanButton.style.opacity = "1";
        } else {
            if (dropzoneContent) dropzoneContent.style.display = "block";
            if (dropzoneSelected) dropzoneSelected.style.display = "none";
            scanButton.disabled = true;
        }
    }

    fileInput.addEventListener("change", (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) updateUI(file);
    });

    ["dragenter", "dragover"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    dropzone.addEventListener("drop", (e) => {
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files[0]) {
            const file = files[0];
            if (!file.name.toLowerCase().endsWith(".apk")) {
                alert("Please select a .apk file");
                return;
            }
            fileInput.files = files;
            updateUI(file);
        }
    });

    if (form) {
        form.addEventListener("submit", () => {
            const btnLabel = scanButton.querySelector(".btn-label");
            const btnSpinner = scanButton.querySelector(".btn-spinner");
            if (btnLabel) btnLabel.textContent = "Scanning...";
            if (btnSpinner) btnSpinner.style.display = "inline-block";
            scanButton.disabled = true;
        });
    }
});
