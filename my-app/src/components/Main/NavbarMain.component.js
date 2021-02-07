import React, { Component } from "react";
import "./NavbarMain.css";
import {
  Navbar,
  Container,
  NavbarBrand,
  Nav,
  Form,
  FormControl,
  Button,
} from "react-bootstrap/";
import "bootstrap/dist/css/bootstrap.min.css";
import SearchIcon from "@material-ui/icons/Search";

export default class Navbars extends Component {
  render() {
    return (
      <div>
        <Navbar bg="light" expand="lg">
          <Container>
            <NavbarBrand>
              <img
                src="https://demo.defectdojo.org/static/dojo/img/logo.png"
                alt="DefectDojo-logo"
                width="240px"
              />
            </NavbarBrand>
            <Navbar.Collapse id="responsive-navbar-nav"></Navbar.Collapse>
            <Form inline>
              <FormControl
                type="text"
                placeholder="Search"
                className="mr-sm-2"
              />
              <Button type="submit">
                <SearchIcon />
              </Button>
            </Form>
            <Navbar.Toggle aria-controls="responsive-navbar-nav" />
          </Container>
        </Navbar>
      </div>
    );
  }
}
