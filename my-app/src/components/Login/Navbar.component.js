import React, { Component } from "react";
import { Navbar, Container, NavbarBrand } from "react-bootstrap/";
import "bootstrap/dist/css/bootstrap.min.css";
import { Link } from "react-router-dom";
import "./Navbar.css";

export default class Navbars extends Component {
  render() {
    return (
      <div>
        <Navbar collapseOnSelect expand="lg" bg="light">
          <Container>
            <NavbarBrand>
              <Link to={"/sign-in"}>DefectDojo</Link>
            </NavbarBrand>
            <Navbar.Toggle aria-controls="responsive-navbar-nav" />
            <Navbar.Collapse id="responsive-navbar-nav">
              <ul className="navbar-nav ml-auto">
                <li className="nav-item">
                  <Link className="nav-link" to={"/sign-in"}>
                    Sign in
                  </Link>
                </li>
                <li className="nav-item">
                  <Link className="nav-link" to={"/sign-up"}>
                    Sign up
                  </Link>
                </li>
              </ul>
            </Navbar.Collapse>
          </Container>
        </Navbar>
      </div>
    );
  }
}
