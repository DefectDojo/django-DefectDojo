/*
 * The MIT License

Copyright (c) 2010, 2011, 2012, 2013 by Juergen Marsch

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

$.plot.JUMExample.docu.rose = {
"docu":"Documentation","rose":{
"docu":"Plugin to show a rose chart","data":{
"docu":"Data Array specific for Rose chart","0":{
"docu":"Values are only the size of the rose"}
}
,"options":{
"docu":" options (general object from FLOT)","series":{
"docu":"series (general object from FLOT)","rose":{
"docu":"specific options for rose plugin","active":{
"docu":"switches binding of plugin into hooks","defVal":"false"}
,"show":{
"docu":"switches show of candlestick on for actual series","defVal":"false"}
,"roseSize":{
"docu":"Size of the rose-circle, maximumsize is 1.0, take care to have some space for lables.","defVal":"0.7"}
,"leafSize":{
"docu":"Value from 0 to 1 giving the space of the pie to be used for the rose","defVal":"0.7"}
,"dataMin":{
"docu":"Minimum value for the rose. This is not calculated form data (yet), so you have to give data.","defVal":"0"}
,"dataMax":{
"docu":"Maximum value for the rose. This is not calculated form data (yet), so you have to give data.","defVal":"100"}
,"drawGrid":{
"docu":"","drawValue":{
"docu":"","defVal":"true"}
,"drawLabel":{
"docu":"","defVal":"true"}
,"labelPos":{
"docu":"","defVal":"0.5"}
,"gridMode":{
"docu":"","defVal":"data"}
}
,"highlight":{
"docu":"Describes how highlighting (in case of HOVER) is displayed","opacity":{
"docu":"Default for highlighting is to change opacity only","defVal":"0.5"}
}
}
}
}
}
}