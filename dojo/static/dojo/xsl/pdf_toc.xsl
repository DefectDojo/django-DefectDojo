<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:outline="http://wkhtmltopdf.org/outline"
                xmlns="http://www.w3.org/1999/xhtml">
    <xsl:output doctype-public="-//W3C//DTD XHTML 1.0 Strict//EN"
                doctype-system="http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
                indent="yes"/>
    <xsl:template match="outline:outline">
        <html>
            <head>
                <title>Table of Contents</title>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
                <style>
                    @import url("https://fonts.googleapis.com/css?family=Raleway:400,700");
                    h1 {
                    text-align: center;
                    font-size: 1.5em;
                    padding: 5px;
                    }
                    div {border-bottom: 1px dotted rgb(200,200,200);}
                    span {float: right;}
                    li {list-style: none;}
                    ul {
                    font-size: 1.2em;
                    font-family: arial;
                    }
                    ul ul {font-size: 80%; }
                    ul {padding-left: 0em;}
                    ul ul {padding-left: 1.5em;}
                    a {text-decoration:none; color: black;}
                    h1,
                    h2,
                    h3,
                    h4,
                    h5,
                    h6{
                    font-family: "Raleway", "Helvetica Neue", Helvetica, Arial, sans-serif;
                    font-weight: bold;
                    line-height: 1.1;
                    color: inherit;
                    }
                </style>
            </head>
            <body>
                <h1>Table of Contents</h1>
                <ul class="leaders">
                    <xsl:apply-templates select="outline:item/outline:item"/>
                </ul>
            </body>
        </html>
    </xsl:template>
    <xsl:template match="outline:item">
        <li>
            <xsl:if test="@title!=''">
                <div>
                    <a>
                        <xsl:if test="@link">
                            <xsl:attribute name="href">
                                <xsl:value-of select="@link"/>
                            </xsl:attribute>
                        </xsl:if>
                        <xsl:if test="@backLink">
                            <xsl:attribute name="name">
                                <xsl:value-of select="@backLink"/>
                            </xsl:attribute>
                        </xsl:if>
                        <xsl:value-of select="@title"/>
                    </a>
                    <span>
                        <xsl:value-of select="@page"/>
                    </span>
                </div>
            </xsl:if>
            <ul class="leaders">
                <xsl:comment>added to prevent self-closing tags in QtXmlPatterns</xsl:comment>
                <xsl:apply-templates select="outline:item"/>
            </ul>
        </li>
    </xsl:template>
</xsl:stylesheet>
