// B2B Travel Portal Client Bundle v2.0.0
// Build hash: e4b7713d8a92
(function() {
  const API_BASE = "/api/v1";
  window.TravelPortal = {
    search: (origin, dest) => fetch(`${API_BASE}/flights/search?origin=${origin}&destination=${dest}`),
    hold: (flightId, seats) => fetch(`${API_BASE}/flights/hold`, {method: "POST", body: JSON.stringify({flight_id: flightId, passengers: seats})}),
    book: (holdId, details) => fetch(`${API_BASE}/bookings`, {method: "POST", body: JSON.stringify({hold_id: holdId, ...details})}),
    getBooking: (bookingId) => fetch(`${API_BASE}/bookings/${bookingId}`),
    pay: (bookingId, amount) => fetch(`${API_BASE}/bookings/${bookingId}/pay`, {method: "POST", body: JSON.stringify({amount: amount})}),
    cancel: (bookingId) => fetch(`${API_BASE}/bookings/${bookingId}/cancel`, {method: "POST"}),
    getCommissions: () => fetch(`${API_BASE}/agency/commissions`),
    applyPromo: (code, amt) => fetch(`${API_BASE}/promotions/apply`, {method: "POST", body: JSON.stringify({promo_code: code, booking_amount: amt})}),
    legacyRates: (carrier) => fetch(`${API_BASE}/legacy/xml-rates?carrier=${carrier}`)
  };
})();
