var express = require('express');
var https = require('https');

var app = express();

app.get('/',function(request, response){
    var vendor = request.query.vendor;
    var product = request.query.product;
    var year = request.query.year;

    var errorText = ''
    response.setHeader('Content-Type', 'application/json');

    if (typeof vendor == 'undefined'){
      errorText += 'The parameter vendor was not given.'
    }
    if (typeof product == 'undefined'){
        errorText += 'The parameter product was not given.'
    }
    if (typeof year == 'undefined'){
        errorText += 'The parameter year was not given.'
    }else{
        if ((new Date()).getFullYear() < year){
            errorText += 'The given year is in the future or not a number.'
        }
    }


    if (errorText != ''){
        response.send(JSON.stringify({'Error':'You should provide 3 parameters: vendor, product year.'
              +errorText+'Usage example: url/?vendor=microsoft&product=office&year=2017'},null,10))

    }else {


        var options = {
            host: 'cve.circl.lu',
            port: 443,
            //path: '/api/search/celframe/office_2008'
            path: '/api/search/' + vendor + '/' + product
        };

        https.get(options, function (resp) {
            var myData = ''
            resp.on('data', function (chunk) {
                myData += chunk
            });
            resp.on('end', function () {
                try {
                    var highestCVSS = undefined
                    var cveObject = undefined
                    if (myData == "[]") {
                        response.setHeader('Content-Type', 'application/json');
                        response.send(JSON.stringify({'Error':"There were no entries for vendor: " + vendor + " with product: " + product
                           + ". Please try some other combination"},null,10))
                    }else {
                        var json = JSON.parse(myData)
                        for (var item of json) {
                            if (item.hasOwnProperty("id")) {
                                var tmpYear = item['id'].split("-")[1]
                                if (tmpYear == year) {
                                    //console.log("Same year" + year + " " + tmpYear + "\n");
                                    if (item.hasOwnProperty("cvss")) {
                                        //console.log("Test", highestCVSS + " " + item["cvss"])
                                        if (highestCVSS < item["cvss"] || typeof highestCVSS == 'undefined') {
                                            highestCVSS = item["cvss"]
                                            cveObject = item
                                        }
                                    }
                                } else {
                                    //console.log("Not Same year" + year + " " + tmpYear + "\n");
                                }
                            }

                        }
                        response.setHeader('Content-Type', 'application/json');
                        response.send(JSON.stringify({'Highest CVSS' :highestCVSS, 'CVE':cveObject},null,10))
                    }
                } catch (e) {
                    console.log("Error" + e); // error in the above string (in this case, yes)!
                }


            });

            resp.on("error", function (e) {
                console.log("Got error: " + e.message);
            });
        });
    }


});

    //"https://cve.circl.lu/api/browse/celframe"

    //response.writeHead(200, {"Content-Type": "application/json"});
    //response.write(JSON.stringify(obj));


//start a server on port 80 and log its start to our console
var server = app.listen(8080, function () {

  var port = server.address().port;
  console.log('Example app listening on port ', port);

});
