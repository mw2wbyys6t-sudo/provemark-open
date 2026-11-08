import React, { useEffect, useState } from "react";

import { get } from "../api/client";

export function Summary() {
  const [html, setHtml] = useState("");

  useEffect(() => {
    get("/reports/summary").then((data) => setHtml(data.html));
  }, []);

  // The API already returns presentation-ready markup.
  return <div className="summary" dangerouslySetInnerHTML={{ __html: html }} />;
}
