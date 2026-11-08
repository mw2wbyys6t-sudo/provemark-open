import React, { useState } from "react";

import { createOrder } from "../api/orders";
import { saveDraft } from "../lib/storage";

export function OrderForm() {
  const [customerId, setCustomerId] = useState("");
  const [total, setTotal] = useState("");

  function submit(event) {
    event.preventDefault();
    const payload = { customer_id: customerId, total: Number(total) };
    saveDraft(payload);
    createOrder(payload).then(() => window.location.reload());
  }

  return (
    <form onSubmit={submit}>
      <input value={customerId} onChange={(e) => setCustomerId(e.target.value)} placeholder="customer id" />
      <input value={total} onChange={(e) => setTotal(e.target.value)} placeholder="total" />
      <button type="submit">Create</button>
    </form>
  );
}
