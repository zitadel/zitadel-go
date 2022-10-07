module.exports = {
    branches: [
        {name: 'v1', range: '0.x.x', channel: '0.x.x'},
    ],
    plugins: [
        "@semantic-release/commit-analyzer",
        "@semantic-release/release-notes-generator",
        "@semantic-release/github"
    ]
};
