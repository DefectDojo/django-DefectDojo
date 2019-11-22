$(function () {
    $('body').append('<a id="toTop" title="Back to Top" class="btn btn-primary btn-circle"><i class="fa fa-fw fa-arrow-up"></i></a>');
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('#toTop').fadeIn();
        } else {
            $('#toTop').fadeOut();
        }
    });

    $('#toTop').click(function(){
        $("html, body").animate({ scrollTop: 0 }, 600);
        return false;
    });


    $(".datepicker").datepicker({"dateFormat": "yy-mm-dd"});

    $('form#replace_risk_file input[type="file"], div.controls.file input').change(function () {
        $(this).closest("form").submit()
    });

    $('a.accept-all-findings').click(function () {
        $("ul#id_accepted_findings input").attr('checked', true);
    })

    setTimeout(function () {
        $('.alert-dismissible').slideUp('slow')
    }, 20000);

    $('#side-menu').metisMenu();

    // auto focus on first form field
    $('#base-content form:first *:input[type!=hidden]:first').not('button, input[type=submit]').not('.filters :input, textarea#id_entry, input#quick_add_finding').focus();

    $('a#minimize-menu').on('click', sidebar);

    $("ul#progress-crumbs a").on('click', function() {
        var href = $(this).attr('href');
        $('html, body').animate({
            scrollTop: $(href).offset().top - 55
        }, 500);
        return false;
    });

});

$.fn.serializeObject = function()
{
    var o = {};
    var a = this.serializeArray();
    $.each(a, function() {
        if (o[this.name] !== undefined && o[this.name] != 'csrfmiddlewaretoken') {
            if (!o[this.name].push) {
                o[this.name] = [o[this.name]];
            }
            o[this.name].push(this.value || '');
        } else {
            o[this.name] = this.value || '';
        }
    });
    return o;
};


function sidebar() {  // minimize side nav bar
    var action = 'min';
    var remove = 'max';
    var speed = 250;
    var width = '50';
    var fontSize = '18';

    if (($.cookie('dojo-sidebar') == 'min') || ($('body').hasClass('min'))) {
        action = 'max';
        remove = 'min';
        $.cookie('dojo-sidebar', 'max', {expires: 10000, path: '/'});
        width = '175px';
        fontSize = '14px';
        speed = 100;
    }
    else {
        action = 'min';
        remove = 'max';
        $.cookie('dojo-sidebar', 'min', {expires: 10000, path: '/'});
    }

    $('body').switchClass(remove, action);

    return false;
}

function emptyEndpoints(win) {
    var name = windowname_to_id(win.name);
    var elem = document.getElementById(name);
    $(elem).empty();
}

function html_unescape(text) {
    // Unescape a string that was escaped using django.utils.html.escape.
    text = text.replace(/&lt;/g, '<');
    text = text.replace(/&gt;/g, '>');
    text = text.replace(/&quot;/g, '"');
    text = text.replace(/&#39;/g, "'");
    text = text.replace(/&amp;/g, '&');
    return text;
}

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
            var s = "#" + elem.id + " option[value='" + newId + "']";
            if ($(s).length <= 0) {
                o = new Option(newRepr, newId);
                elem.options[elem.options.length] = o;
                o.selected = true
                $(o).attr('selected', 'selected');
            }
            else {
                $(s).attr('selected', 'selected');
            }
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
                        yeah = Math.ceil(flotItem.series.data[x][2] * highest_count);
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

function togglePassVisibility() {
    var passwdInput = document.getElementById("id_password");
    var toggleBox = document.getElementById("toggleBox");
    
    // swap password
    if (passwdInput.type === "password") {
        passwdInput.type = "text";
        toggleBox.innerHTML = "<i class='fa fa-eye-slash'></i>\
        <span><b>Hide Password</b></span>";
    } else {
        passwdInput.type = "password";
        toggleBox.innerHTML = "<i class='fa fa-eye'></i>\
        <span><b>Show Password</b></span>";
    }
} 

function asciidocDownload() {
    var content = document.getElementById('base-content')
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + 
        encodeURIComponent(content.innerText.slice(16)));
    element.setAttribute('download', 'asciidoc-report.txt');
  
    element.style.display = 'none';
    document.body.appendChild(element);
  
    element.click();
  
    document.body.removeChild(element);
  }


// Parse a string that contains HTML to retrieve value from the HTML tag or Attribute, returning only a TEXT version.
// The htmlTagAttributValye is optional, and if supplied, then this function will look within the HTML tag attributes to
// return the value. Example htmlTagAttributValye ( data-content=****** )
// This function is used in the product.html,  view_product_details adn engagements_all for proper DataTables exports.
function getDojoExportValueFromTag(htmlString, tag, htmlTagAttribValue){
    parser = new DOMParser();
    doc = parser.parseFromString(htmlString.toString(), "text/html");
    var tags = doc.getElementsByTagName(tag.toString());
    var l = tags.length;
    var tagsValueArray = [];
    var exportValue = "";
    if (htmlTagAttribValue) {
        for (i = 0; i < l; i++) {
            var tempAttribValue = tags[i].getAttribute(htmlTagAttribValue.toString());
            // Only append values if they are not null, empty or NaN
            if (tempAttribValue) {
                tagsValueArray.push(tempAttribValue);
            }
        }
        exportValue = tagsValueArray;
    }
    else {
        if (l >= 1) {
            // Iterate through all HTML tags and append the return values to the array
            for (i = 0; i < l; i++) {
                tagsValueArray.push(tags[i].textContent);
            }
            exportValue = tagsValueArray;
        }
    else {
        exportValue = htmlString;
    }}

    // Replace by a space any HTML tags that might still be in the string
    return exportValue.toString().replace(/<\/?[^>]+(>|$)/g, " ");
}