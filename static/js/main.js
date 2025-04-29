function handleSubmit(form) {
    let domain = form.domain.value;
    domain = domain.replace(/^https?:\/\//, '')  // Remove http:// or https://
                 .replace(/^www\./, '')          // Remove www.
                 .replace(/\/$/, '');            // Remove trailing slash
    window.location.href = '/results/' + domain;
}