import { get, post } from "./client";

export function fetchOrders(status = "open") {
  return get(`/orders?status=${status}`);
}

export function createOrder(payload) {
  return post("/orders", payload);
}

export function fetchOrder(id) {
  return get(`/orders/${id}`);
}
