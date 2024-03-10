import { Card, CardContent, CardHeader, Skeleton } from "@mui/material";

export function DeviceListItemSkeleton() {
    return(

        <Card>
        <CardHeader
        title={<Skeleton variant="text" width={100} />}
        subheader={<Skeleton variant="text" width={50} />}
        avatar={<Skeleton variant="circular" width={40} height={40} />}
        action={<Skeleton variant="text" width={50} />}
        />
        <CardContent>
        <table cellPadding="5">
            <tbody>
            <tr>
                <td>Endpoint</td>
                <td><Skeleton variant="text" width={100} /></td>
            </tr>
            <tr>
                <td>Download</td>
                <td><Skeleton variant="text" width={100} /></td>
            </tr>
            <tr>
                <td>Upload</td>
                <td><Skeleton variant="text" width={100} /></td>
            </tr>
            <tr>
                <td>Public key</td>
                <td><Skeleton variant="text" width={100} /></td>
            </tr>
            <tr>
                <td>Pre-shared key</td>
                <td><Skeleton variant="text" width={100} /></td>
            </tr>
            </tbody>
        </table>
        </CardContent>
        </Card>
    )

}
