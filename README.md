###Read API Javascript SDK  
For in-depth information about our API and SDK offerings, check out the [developer portal](https://developer.bandpage.com/sdk/Javascript_SDK)  

##Quick start
**Get a Band's Info**  

    $(function() {

        var credential = {
            client_id: 'YOUR_CLIENT_ID',
            shared_secret: 'YOUR_SHARED_SECRET',
            access_token: 'YOUR_ACCESS_TOKEN',
            token_type: 'bearer',
            token_expiration: TOKEN_EXPIRATION
        }

        bandpage.api.init(credential, config);

        bandpage.api.get({
            bid:'A_BANDS_BID',
            done: function(){
                console.log('success!');
                console.dir(arguments);
            }, 
            fail: function(){   
                console.log('failed!');
                console.dir(arguments);
            }
        })
    });

##Initialization

**Initializing the BandPage API module in the browser**  
Download the SDK library file to a location within your web application and drop it onto your page.
    
    <script src="//path/to/js-sdk.0.1.js"></script>  

  
**Auth Credential**  
  
The credential object must be created with an 'access_token' key.  
This token can be retrieved via a server running our sdk and passed to the browser.  
If you have a php backend, see the [php sdk](https://developer.bandpage.com/sdk/PHP) to build a token server.


  
**Transport Config**  
The init method can take a config object with a transport function.  
The transport function is the sdk's mechanism for modularizing requests and responses.  
The transport makes a request and then executes done or fail callbacks with the payload and response.  

Developers who need to can add a "transport" config property which should be a function.  
This can be useful if the default transport strategies are not compatable with your framework or other code.  
It also helps us unit test the sdk code in isolation and integration test for the environments of the default transports.  
  
    <script>
        var credential = {
            client_id: 'YOUR_CLIENT_ID',
            shared_secret: 'YOUR_SHARED_SECRET',
            access_token: 'YOUR_ACCESS_TOKEN',
            token_type: 'bearer',
            token_expiration: TOKEN_EXPIRATION
        },
        config = {
            "transport": function(request, done, fail) {
                var data = {},
                    response = {},
                    userReq = {},
                    userResponse = {};
                
                // use some of the provided request info to make your request
                userReq.url = request.url;
                userReq.headers = request.headers;

                try {
                    userRequest(userReq, function(response) {
                        // depending on how things go, trigger the
                        // done and fail callbacks appropriately
                        if (response.statuscode === 200 && response.coolness > 0) {
                            userResponse.headers = response.headers;
                            done(response.body, userResponse);
                        } else {
                            fail({"error": "that response wasn't very cool"});
                        }
                    });
                } catch (e) {
                    fail(e);
                }


            }
        }
        bandpage.api.init(credential, config);
    </script>  

1. Use console.dir or similar to see the request object properties. Then grab the data you need for constructing your own request.

2. Then make the request via your favorite framework.  

3. When the result is returned, create a response object and return it along with the data.
If something goes wrong, then return an error as an argument to the fail callback.



##Public Methods  
If any public methods are called without any of the required options, the sdk will throw an error.

**Required Options**  
All public methods require done and fail callbacks to be passed as keys on an options object.  
  
- done  
        function done(data, response) {}  
- fail  
        function fail(errorObject) {}  

###Get  
Retrieve a graph object.

**Required Options**  
- bid - the unique BID of the object that you would like to retrieve
  
    var options = {
        'bid' : A_BANDS_BID,
        'done': function(band, response) {
            console.log(arguments);
        },
        'fail': function(data, response) {
            console.log("could not retrieve bid data.");
        }
    };
    bandpage.api.get(options);

###GetConnections
Retrieving data connected to a graph object 

**Required Options**  
- bid - the unique bid of the object that you would like to retrieve 
- connection_type - the kind of connection objects to retrieve  
possible values are: Event, Photo, PhotoAlbum, Playlist, Track, Video  

**Optional Options**  
- since - The time after which results should be retrieved
- until - The time before which results should be retrieved
- limit - Limit the number of objects returned per page

**Paging**  
The connections may have many pages of data.  
Pages can be retireved within the done callback, by checking the response object for a getNextPage function.  
if it is not null, then it can be called in order to retrieve the next page of data from the same query like so:  
    
    // set up the array for the result set and create your callbacks
    var tracksdatapages = [],
        fail = function(e) {
            // do something with the error object
        },
        pagableDone = function done(tracksdata, response) {

            // add the data page to an array and get another
            if(tracksdata !== null) {
                
                tracksdatapages.push(tracksdata);
                
                if(typeof response.getNextPage === "function") {
                    response.getNextPage(done, fail);
                    return;
                }

            }

            return;
        };

    // put them in an object
    var options = {
        "bid": 'A_BANDS_BID',
        "connection_type": 'tracks',
        "done": pageableDone,
        "fail": fail
    }

    // then calling the function as usual
    bandpage.api.getConnections(options);

