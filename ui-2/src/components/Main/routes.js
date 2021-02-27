import { Dashboard } from "@material-ui/icons";
import DashboardPage from "./views/Dashboard";
import Person from "@material-ui/icons/Person";
const dashboardRouters = [
  {
    path: "/dashboard",
    name: "Dashboard",
    icon: Dashboard,
    component: DashboardPage,
  },
  {
    path: "/product",
    name: "Product",

    icon: Person,
  },
];
export default dashboardRouters;
