import React, { useEffect, useState } from "react";
import _ from "lodash";

import { fetchOrders } from "../api/orders";
import { formatMoney, formatDate } from "../lib/format";

export function OrderList() {
  const [rows, setRows] = useState([]);

  useEffect(() => {
    fetchOrders().then((data) => setRows(_.sortBy(data, "id")));
  }, []);

  return (
    <table className="orders">
      <thead>
        <tr>
          <th>#</th>
          <th>Customer</th>
          <th>Status</th>
          <th>Total</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.id}>
            <td>{row.id}</td>
            <td>{row.customer_id}</td>
            <td>{row.status}</td>
            <td>{formatMoney(row.total)}</td>
            <td>{formatDate(row.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
