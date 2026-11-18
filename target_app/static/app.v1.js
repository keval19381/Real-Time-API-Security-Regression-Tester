// B2B Travel Portal Client Bundle v1.0.0
// Build hash: 8f23c91a0d4e
(function() {
  const API_BASE = "/api/v1";
  window.TravelPortal = {
    search: (origin, dest) => fetch(`${API_BASE}/flights/search?origin=${origin}&destination=${dest}`),
    hold: (flightId, seats) => fetch(`${API_BASE}/flights/hold`, {method: "POST", body: JSON.stringify({flight_id: flightId, passengers: seats})}),
    book: (holdId, details) => fetch(`${API_BASE}/bookings`, {method: "POST", body: JSON.stringify({hold_id: holdId, ...details})}),
    getBooking: (bookingId) => fetch(`${API_BASE}/bookings/${bookingId}`),
    legacyRates: (carrier) => fetch(`${API_BASE}/legacy/xml-rates?carrier=${carrier}`)
  };
})();
