function analyzeQuery() {
    const input = document.getElementById('queryInput').value.trim();
    if (!input) {
        alert('Please enter a query to analyze!');
        return;
    }

    // Show loading state
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');

    // Send request to Flask backend
    fetch('/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ text: input })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            throw new Error(data.error);
        }
        displayResults(data);
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error analyzing query: ' + error.message);
    })
    .finally(() => {
        document.getElementById('loading').classList.add('hidden');
    });
}

function displayResults(data) {
    // Query type and sentiment
    document.getElementById('queryType').innerHTML =
        `<span class="query-type">${data.query_type.replace(/_/g, ' ')}</span>`;

    const sentiment = data.entities.sentiment;
    const sentimentClass = `sentiment-${sentiment.label.toLowerCase()}`;
    document.getElementById('sentiment').innerHTML =
        `<span class="sentiment ${sentimentClass}">${sentiment.label} (${(sentiment.confidence * 100).toFixed(1)}%)</span>`;

    // Custom entities
    const customEntitiesHtml = data.entities.custom_entities
        .map(entity => {
            const className = `entity-${entity.label.toLowerCase().replace('_', '-')}`;
            return `<span class="entity ${className}">${entity.text} (${entity.label})</span>`;
        })
        .join(' ');
    document.getElementById('customEntities').innerHTML =
        customEntitiesHtml || '<span class="token">No cybersecurity entities detected</span>';

    // Standard entities
    const standardEntitiesHtml = data.entities.standard_entities
        .map(entity => `<span class="entity entity-standard">${entity.text} (${entity.label})</span>`)
        .join(' ');
    document.getElementById('standardEntities').innerHTML =
        standardEntitiesHtml || '<span class="token">No standard entities detected</span>';

    // Tokens
    const tokensHtml = data.entities.tokens
        .map(token => `<span class="token">${token}</span>`)
        .join(' ');
    document.getElementById('tokens').innerHTML = tokensHtml;

    // Mock response
    document.getElementById('mockResponse').textContent = data.response;

    // Routing explanation
    document.getElementById('routingExplanation').textContent = data.routing_explanation;

    // Show results
    document.getElementById('results').classList.remove('hidden');
}

function setExample(text) {
    document.getElementById('queryInput').value = text;
    analyzeQuery();
}