 // JavaScript to handle arrow rotation
 console.log("ding")
 document.querySelectorAll('.dropdown-toggle').forEach(function (dropdown) {
    console.log("Welcome !")
    dropdown.addEventListener('click', function () {
        let arrow = this.querySelector('.right_arrow');
        if (arrow) {
            arrow.style.transform = this.getAttribute('aria-expanded') === 'true' ? 'rotate(0deg)' : 'rotate(90deg)';
        }
    });
});