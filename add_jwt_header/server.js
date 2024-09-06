const http = require('http');

// Create an HTTP server
const server = http.createServer((req, res) => {
    // Extract headers and cookies from the request
    const headers = req.headers;
    const cookies = headers.cookie || 'No cookies found';

    // Set the response headers
    res.setHeader('Content-Type', 'application/json');

    // Respond with the headers and cookies in JSON format
    res.writeHead(200);
    res.end(JSON.stringify({
        message: "Headers and Cookies received",
        headers: headers,
        cookies: cookies
    }, null, 2));
});

// Listen on port 3000
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
