import React from "react";
import { createRoot } from "react-dom/client";

import { OrderList } from "./components/OrderList";
import { OrderForm } from "./components/OrderForm";
import { Summary } from "./components/Summary";

const root = createRoot(document.getElementById("root"));

root.render(
  <div className="orderdesk">
    <Summary />
    <OrderForm />
    <OrderList />
  </div>
);
