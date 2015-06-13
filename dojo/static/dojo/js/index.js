$(function () {
    $(".datepicker").datepicker();

    $.tablesorter.addParser({
        id: 'severity',
        is: function (s) {
            return false;
        },
        format: function (s) {
            return s.toLowerCase().replace(/critical/, 0).replace(/high/, 1).replace(/medium/, 2).replace(/low/, 3).replace(/info/, 4);
        },
        type: 'numeric'
    });

    $('#tabs').tabs();

    $('form#replace_risk_file input[type="file"], div.controls.file input').change(function () {
        $(this).closest("form").submit()
    });

    $('a.accept-all-findings').click(function () {
        $("ul#id_accepted_findings input").attr('checked', true);
    })


    setTimeout(function () {
        $('.alert-dismissible').slideUp('slow')
    }, 20000);


});

$(function () {

    $('#side-menu').metisMenu(
        {doubleTapToGo: true}
    );

});

function dismissAddAnotherPopupDojo(win, newId, newRepr) {
    // newId and newRepr are expected to have previously been escaped by
    // django.utils.html.escape.
    newId = html_unescape(newId);
    newRepr = html_unescape(newRepr);
    var name = windowname_to_id(win.name);
    var elem = document.getElementById(name);
    var o;
    if (elem) {
        var elemName = elem.nodeName.toUpperCase();
        if (elemName == 'SELECT') {
            o = new Option(newRepr, newId);
            elem.options[elem.options.length] = o;
            o.selected = true;
        } else if (elemName == 'INPUT') {
            if (elem.className.indexOf('vManyToManyRawIdAdminField') != -1 && elem.value) {
                elem.value += ',' + newId;
            } else {
                elem.value = newId;
            }
        }
    } else {
        var toId = name + "_to";
        o = new Option(newRepr, newId);
        SelectBox.add_to_cache(toId, o);
        SelectBox.redisplay(toId);
    }
}

function punchcard(element, data, ticks) {
    var d1 = data;
    var options = {
        xaxis: {
            ticks: ticks,
            min: -.8,
            max: ticks.length - .2,
            tickLength: 0,
        },
        series: {
            bubbles: {
                active: true,
                debug: {
                    active: false
                },
                show: true,
                bubblelabel: {
                    show: false,
                },
            },
            nearBy: {
                distance: 5
            }
        },
        yaxis: {
            autoscaleMargin: 0.1,
            ticks: [[6, 'Sun'], [5, 'Mon'], [4, 'Tue'], [3, 'Wed'], [2, 'Thur'], [1, 'Fri'], [0, 'Sat']],
            min: -.5,
            max: 6.5,
            tickLength: 0,
        },
        grid: {
            hoverable: true,
            borderWidth: {top: 0, right: 0, bottom: 1, left: 0},
            borderColor: '#e7e7e7',
            clickable: true,
            markings: function (axes) {
                var markings = [];

                for (var x = 0; x < axes.yaxis.max; x += .5)
                    markings.push({yaxis: {from: x, to: x},});

                for (var x = -0; x < axes.xaxis.max; x += 1)
                    markings.push({xaxis: {from: x, to: x}});

                for (var x = -.5; x < axes.yaxis.max + 1; x += 1)
                    markings.push({yaxis: {from: x, to: x - .75}, color: 'white'});


                return markings;


            }
        },
        tooltip: true,
        tooltipOpts: {
            content: function (label, xval, yval, flotItem) {
                for (var x = 0; x < flotItem.series.data.length; x++) {
                    if (xval == flotItem.series.data[x][0] && yval == flotItem.series.data[x][1]) {
                        yeah = Math.ceil(flotItem.series.data[x][2]*highest_count);
                        break;
                    }
                }
                if (yeah <= 0) {
                    return;
                }
                return yeah + ' Findings';
            },
            shifts: {
                y: -40,
                x: -20
            }
        },
        legend: {
            show: false,
        }


    };
    var p4 = $.plot($(element),
        [{
            data: d1,
            color: "#444",
        }],
        options);

}

