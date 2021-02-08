import React, { Component } from "react";
import "./NavbarMain.css";

import {
  Navbar,
  NavDropdown,
  Nav,
  Button,
  Form,
  FormControl,
} from "react-bootstrap";

import "bootstrap/dist/css/bootstrap.min.css";
import SearchIcon from "@material-ui/icons/Search";
import NotificationsIcon from "@material-ui/icons/Notifications";

export default class Navbars extends Component {
  render() {
    return (
      <div className="Navbars">
        <Navbar bg="light" variant="light">
          <Nav className="mr-auto">
            <Navbar.Brand href="#home">
              <img
                src="https://demo.defectdojo.org/static/dojo/img/logo.png"
                alt="DefectDojo-logo"
                width="240px"
              />
            </Navbar.Brand>
          </Nav>
          <Form inline>
            <FormControl
              type="text"
              placeholder="Search"
              className="mr-sm-2"
              label="Search"
              aria-label="Search"
              name="query"
            />
            <Button
              variant="dark"
              id="submit_Search"
              aria-label="Serach"
              size="sm"
            >
              <SearchIcon />
            </Button>
          </Form>

          <NavDropdown title={<NotificationsIcon />} id="basic-nav-dropdown">
            <NavDropdown.Item href="#action/3.1">Action</NavDropdown.Item>
            <NavDropdown.Item href="#action/3.2">
              Another action
            </NavDropdown.Item>
            <NavDropdown.Item href="#action/3.3">Something</NavDropdown.Item>
            <NavDropdown.Divider />
            <NavDropdown.Item href="#action/3.4">
              Separated link
            </NavDropdown.Item>
          </NavDropdown>
        </Navbar>
      </div>
    );
  }
}
