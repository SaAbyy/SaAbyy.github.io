document.addEventListener('DOMContentLoaded', function () {
  const filters = document.querySelectorAll('.filter-btn');
  const cards = document.querySelectorAll('#writeup-list .writeup-card');

  if (!filters.length) return;

  filters.forEach(function (btn) {
    btn.addEventListener('click', function () {
      const filter = this.dataset.filter;

      filters.forEach(function (b) { b.classList.remove('active'); });
      this.classList.add('active');

      cards.forEach(function (card) {
        const cat = card.dataset.category || '';
        if (filter === 'all' || cat === filter) {
          card.style.display = '';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });
});
