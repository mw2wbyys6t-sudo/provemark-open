# API reference

| Method | Path                  | Notes                                |
| ------ | --------------------- | ------------------------------------ |
| GET    | `/api/orders`         | `status` filter, defaults to `open`  |
| POST   | `/api/orders`         | body: `customer_id`, `total`         |
| GET    | `/api/orders/{id}`    | single order                         |
| POST   | `/api/users/lookup`   | support console lookup by email      |
| POST   | `/api/users/import`   | bulk import from a CSV export        |
| GET    | `/api/reports/daily`  | `formula` is evaluated server-side   |
| POST   | `/api/reports/restore`| restores a pickled snapshot          |

## Auth

The console sends `Authorization: Bearer <jwt>`. The API currently decodes the
token without verifying the signature so that the staging fixtures keep working.
