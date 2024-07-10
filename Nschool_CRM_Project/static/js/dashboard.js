// function toggleDropdown(element) {
//     // Close all dropdowns
//     console.log("hello")
//     const allDropdowns = document.querySelectorAll('.dropdown-menu');
//     console.log(allDropdowns)
//     allDropdowns.forEach(dropdown => {
//         if (dropdown !== element.nextElementSibling) {
//             dropdown.classList.remove('show');
//         }
//     });

//     // Close all arrows
//     const allArrows = document.querySelectorAll('.right_arrow');
//     allArrows.forEach(arrow => {
//         if (arrow !== element.querySelector('.right_arrow')) {
//             arrow.classList.remove('arrow_user');
//         }
//     });

//     // Toggle the clicked dropdown and arrow
//     const dropdownMenu = element.nextElementSibling;
//     dropdownMenu.classList.toggle('show');
//     dropdownMenu.allDropdowns.style.transition = "all 2s";
//     const rightArrow = element.querySelector('.right_arrow');
//     rightArrow.classList.toggle('arrow_user');
// }