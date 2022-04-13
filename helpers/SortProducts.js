// Sort paginated products
module.exports = function (products, sortValue) {
  let sortedProducts = products;

  if (sortValue === 'SORT_OLDEST') {
    sortedProducts = sortedProducts
      .sort(
        (previous, current) => new Date(previous.date) - new Date(current.date),
      );
  }

  if (sortValue === 'SORT_NEWEST') {
    sortedProducts = sortedProducts
      .sort(
        (previous, current) => new Date(current.date) - new Date(previous.date),
      );
  }

  if (sortValue === 'SORT_CHEAPEST') {
    sortedProducts = sortedProducts
      .sort(
        (previous, current) => previous.discountPrice - current.discountPrice,
      );
  }

  if (sortValue === 'SORT_EXPENSIVEST') {
    sortedProducts = sortedProducts
      .sort(
        (previous, current) => current.discountPrice - previous.discountPrice,
      );
  }

  if (sortValue === 'SORT_NAME') {
    sortedProducts = sortedProducts
      .sort(
        (previous, current) => previous.name.localeCompare(current.name),
      );
  }

  if (sortValue === 'SORT_DISCOUNT') {
    sortedProducts = sortedProducts
      .sort((previous, current) => {
        const currentDiscount = current.price - current.discountPrice;
        const previousDiscount = previous.price - previous.discountPrice;

        return currentDiscount - previousDiscount;
      });
  }

  return sortedProducts;
};
