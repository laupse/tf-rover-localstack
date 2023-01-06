import sys
import dagger


def main():
    with dagger.Connection(dagger.Config(log_output=sys.stdout)) as client:

        src = client.host().directory(".")
        tf = (client
              .container()
              .from_("hashicorp/terraform:1.4.0-alpha20221207")
              )

        static_file_zip = (client
                           .container()
                           .from_("im2nguyen/rover")
                           .with_entrypoint([])
                           .with_secret_variable("AWS_ACCESS_KEY_ID", client.host().env_variable("AWS_ACCESS_KEY_ID").secret())
                           .with_secret_variable("AWS_SECRET_ACCESS_KEY", client.host().env_variable("AWS_SECRET_ACCESS_KEY").secret())
                           .with_env_variable("TF_LOG", "TRACE")
                           .with_workdir("./tf")
                           .with_file("/usr/local/bin/terraform", tf.file("/bin/terraform"))
                           .with_directory("./", src)
                           .exec(["rover", "-standalone"])
                           .file("rover.zip")
                           )

        _ = (client
             .container()
             .from_("alpine:3.17")
             .with_workdir("./build")
             .with_file("rover.zip", static_file_zip)
             .exec(["unzip", "rover.zip"])
             .exec(["rm", "rover.zip"])
             .directory(".")
             .export("build")
             )


if __name__ == "__main__":
    main()
