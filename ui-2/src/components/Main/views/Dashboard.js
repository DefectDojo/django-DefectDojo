import React from "react";
import { makeStyles } from "@material-ui/core/styles";
import AdjustIcon from "@material-ui/icons/Adjust";
import BugReport from "@material-ui/icons/BugReport";

//core components
import GridItem from "../MainComponent/Grid/GridItem";
import GridContainer from "../MainComponent/Grid/GridContainer";
import Card from "../MainComponent/Card/Card";
import CardHeader from "../MainComponent/Card/CardHeader";
import CardIcon from "../MainComponent/Card/CardIcon";
import CardBody from "../MainComponent/Card/CardBody";
import CardFooter from "../MainComponent/Card/CardFooter";

import styles from "../Styles/jss/views/dashboardStyles";

const useStyles = makeStyles(styles);
function Dashboard() {
  const classes = useStyles();
  return (
    <div>
      <GridContainer>
        <GridItem xs={12} sm={6} md={3}>
          <Card>
            <CardHeader color="warning" stats icon>
              <CardIcon color="warning">
                <AdjustIcon fontSize="large" />
              </CardIcon>
              <p className={classes.cardCategory}>Active Engagements</p>
              <h3 className={classes.cardTitle}>8</h3>
            </CardHeader>
            <CardFooter stats>
              <div className={classes.stats}>
                <a href="#pablo" onClick={(e) => e.preventDefault()}>
                  View Engagement Detail.
                </a>
              </div>
            </CardFooter>
          </Card>
        </GridItem>
        <GridItem xs={12} sm={6} md={3}>
          <Card>
            <CardHeader color="success" stats icon>
              <CardIcon color="success">
                <BugReport />
              </CardIcon>
              <p className={classes.cardCategory}>Last Seven Days</p>
              <h3 className={classes.cardTitle}>7</h3>
            </CardHeader>
            <CardFooter stats>
              <div className={classes.stats}>
                <a href="#pablo" onClick={(e) => e.preventDefault()}>
                  View Finding Detail
                </a>
              </div>
            </CardFooter>
          </Card>
        </GridItem>
        <GridItem xs={12} sm={6} md={3}>
          <Card>
            <CardHeader color="success" stats icon>
              <CardIcon color="success">
                <div className={classes.fire_img}>
                  <img src="./Images/fire.png" alt="fire E" />
                </div>
              </CardIcon>
              <p className={classes.cardCategory}>Closed In Last Seven Days</p>
              <h3 className={classes.cardTitle}>0</h3>
            </CardHeader>
            <CardFooter stats>
              <div className={classes.stats}>Last 24 Hours</div>
            </CardFooter>
          </Card>
        </GridItem>
      </GridContainer>
    </div>
  );
}

export default Dashboard;
