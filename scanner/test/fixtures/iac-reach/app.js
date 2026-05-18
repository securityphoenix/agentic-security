// Application code references the exposed S3 bucket.
const bucket = "my-public-bucket";
const obj = await s3.getObject({ Bucket: bucket, Key: req.params.key });
res.send(obj.Body);
