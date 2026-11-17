const photo = document.querySelector('#photo');
if (photo) {
    const maxMb = Number(photo.dataset.maxMb);
    const orientation = document.querySelector('#photo-orientation');
    const preview = document.querySelector('#photo-preview');
    let previewUrl;

    orientation.addEventListener('change', () => {
        preview.dataset.orientation = orientation.value;
    });
    preview.addEventListener('load', () => { preview.hidden = false; });
    photo.addEventListener('change', () => {
        const file = photo.files[0];
        const tooLarge = file && file.size > maxMb * 1024 * 1024;
        photo.setCustomValidity(tooLarge ? `Choose an image no larger than ${maxMb} MB.` : '');

        preview.hidden = true;
        preview.removeAttribute('src');
        if (previewUrl) {
            URL.revokeObjectURL(previewUrl);
            previewUrl = undefined;
        }
        if (file && !tooLarge) {
            preview.dataset.orientation = orientation.value;
            previewUrl = URL.createObjectURL(file);
            preview.src = previewUrl;
        }
    });
}

const resetToken = document.querySelector('#reset-token');
if (resetToken) {
    const token = window.location.hash.slice(1);
    if (/^[a-f0-9]{64}$/.test(token)) {
        resetToken.value = token;
        document.querySelector('#reset-button').disabled = false;
    } else {
        document.querySelector('#reset-error').hidden = false;
    }
    history.replaceState(null, '', window.location.pathname + window.location.search);
}

